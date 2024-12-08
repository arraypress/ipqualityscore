<?php

declare( strict_types=1 );

namespace ArrayPress\IPQualityScore;

use ArrayPress\IPQualityScore\Response\IP;
use ArrayPress\IPQualityScore\Response\Email;
use ArrayPress\IPQualityScore\Response\RequestList;
use ArrayPress\IPQualityScore\Response\Transaction;
use ArrayPress\IPQualityScore\Response\Phone;
use ArrayPress\IPQualityScore\Response\URL;
use ArrayPress\IPQualityScore\Response\LeakCheck;
use ArrayPress\IPQualityScore\Response\CreditUsage;
use ArrayPress\IPQualityScore\Response\EntryList;
use ArrayPress\IPQualityScore\Response\CountryList;
use ArrayPress\IPQualityScore\Response\FraudReport;
use WP_Error;

/**
 * Class Client
 *
 * A comprehensive utility class for interacting with the IPQualityScore API service.
 */
class Client {

	/**
	 * API key for IPQualityScore
	 *
	 * @var string
	 */
	private string $api_key;

	/**
	 * Base URL for the IPQualityScore API
	 *
	 * @var string
	 */
	private const API_BASE = 'https://ipqualityscore.com/api/json/';

	/**
	 * Whether to enable response caching
	 *
	 * @var bool
	 */
	private bool $enable_cache;

	/**
	 * Cache expiration time in seconds
	 *
	 * @var int
	 */
	private int $cache_expiration;

	/**
	 * Strictness level for API calls
	 *
	 * @var int
	 */
	private int $strictness = 0;

	/**
	 * Whether to allow public access points
	 *
	 * @var bool
	 */
	private bool $allow_public_access_points = false;

	/**
	 * Whether to use lighter penalties
	 *
	 * @var bool
	 */
	private bool $lighter_penalties = false;

	/**
	 * Valid types and their corresponding value_types
	 */
	private const ALLOWLIST_TYPES = [
		'proxy'         => [ 'ip', 'cidr', 'isp' ],
		'devicetracker' => [ 'deviceid', 'ip', 'cidr', 'isp' ],
		'mobiletracker' => [ 'deviceid', 'ip', 'cidr', 'isp' ],
		'email'         => [ 'email' ],
		'url'           => [ 'domain' ],
		'phone'         => [ 'phone' ],
		'custom'        => null // accepts any value_type for custom variables
	];

	/**
	 * API Endpoint patterns and their configurations
	 */
	private const ENDPOINTS = [
		// Simple GET endpoints with value after API key
		'phone'            => [
			'pattern'     => '%s%s/%s/%s', // base/endpoint/api_key/value
			'method'      => 'GET',
			'value_param' => 'phone'
		],
		'ip'               => [
			'pattern'     => '%s%s/%s/%s', // base/endpoint/api_key/value
			'method'      => 'GET',
			'value_param' => 'ip'
		],
		'url'              => [
			'pattern'      => '%s%s/%s/%s', // base/endpoint/api_key/value
			'method'       => 'GET',
			'value_param'  => 'url',
			'encode_value' => true
		],
		// Special GET endpoints
		'leaked'           => [
			'pattern'      => '%s%s/%s/%s/%s', // base/endpoint/type/api_key/value
			'method'       => 'GET',
			'type_param'   => 'type',
			'value_param'  => 'value',
			'encode_value' => true
		],
		'account'          => [
			'pattern' => '%s%s/%s', // base/endpoint/api_key
			'method'  => 'GET'
		],
		// List endpoints (GET)
		'allowlist/list'   => [
			'pattern' => '%s%s/%s/list', // base/endpoint_base/api_key/list
			'method'  => 'GET'
		],
		'blocklist/list'   => [
			'pattern' => '%s%s/%s/list', // base/endpoint_base/api_key/list
			'method'  => 'GET'
		],
		// POST endpoints
		'allowlist/create' => [
			'pattern' => '%s%s/%s', // base/endpoint/api_key
			'method'  => 'POST'
		],
		'allowlist/delete' => [
			'pattern' => '%s%s/%s', // base/endpoint/api_key
			'method'  => 'POST'
		],
		'blocklist/create' => [
			'pattern' => '%s%s/%s', // base/endpoint/api_key
			'method'  => 'POST'
		],
		'blocklist/delete' => [
			'pattern' => '%s%s/%s', // base/endpoint/api_key
			'method'  => 'POST'
		],
		'transaction'      => [
			'pattern' => '%s%s/%s', // base/endpoint/api_key
			'method'  => 'POST'
		]
	];

	/**
	 * Initialize the IPQualityScore client
	 *
	 * @param string $api_key          API key for IPQualityScore
	 * @param bool   $enable_cache     Whether to enable caching (default: true)
	 * @param int    $cache_expiration Cache expiration in seconds (default: 1 hour)
	 */
	public function __construct( string $api_key, bool $enable_cache = true, int $cache_expiration = 3600 ) {
		$this->api_key          = $api_key;
		$this->enable_cache     = $enable_cache;
		$this->cache_expiration = $cache_expiration;
	}

	/**
	 * Set the strictness level
	 *
	 * @param int $strictness Level from 0-3
	 */
	public function set_strictness( int $strictness ): void {
		$this->strictness = max( 0, min( 3, $strictness ) );
	}

	/**
	 * Set whether to allow public access points
	 *
	 * @param bool $allow
	 */
	public function set_allow_public_access_points( bool $allow ): void {
		$this->allow_public_access_points = $allow;
	}

	/**
	 * Set whether to use lighter penalties
	 *
	 * @param bool $use_lighter
	 */
	public function set_lighter_penalties( bool $use_lighter ): void {
		$this->lighter_penalties = $use_lighter;
	}

	/**
	 * Make a request to the IPQualityScore API
	 *
	 * @param string $endpoint API endpoint
	 * @param array  $params   Query parameters
	 * @param array  $args     Additional request arguments
	 *
	 * @return array|WP_Error Response array or WP_Error on failure
	 */
	private function make_request( string $endpoint, array $params = [], array $args = [] ) {
		// Add common parameters
		$params = array_merge( [
			'strictness'                 => $this->strictness,
			'user_agent'                 => $_SERVER['HTTP_USER_AGENT'] ?? '',
			'user_language'              => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
			'allow_public_access_points' => $this->allow_public_access_points,
			'lighter_penalties'          => $this->lighter_penalties,
			'fast'                       => false,
		], $params );

		// Get endpoint configuration
		$config = self::ENDPOINTS[ $endpoint ] ?? [
			'pattern' => '%s%s/%s',
			'method'  => 'POST'
		];

		// Build URL based on endpoint configuration
		$url_params = [ self::API_BASE, $endpoint, $this->api_key ];

		// Add type and value parameters for special endpoints
		if ( isset( $config['type_param'] ) && isset( $params[ $config['type_param'] ] ) ) {
			$url_params[] = $params[ $config['type_param'] ];
			unset( $params[ $config['type_param'] ] );
		}

		if ( isset( $config['value_param'] ) && isset( $params[ $config['value_param'] ] ) ) {
			$value = $params[ $config['value_param'] ];
			if ( ! empty( $config['encode_value'] ) ) {
				$value = urlencode( $value );
			}
			$url_params[] = $value;
			unset( $params[ $config['value_param'] ] );
		}

		$url = sprintf( $config['pattern'], ...$url_params );

		// Add remaining parameters as query string for GET requests
		if ( $config['method'] === 'GET' && ! empty( $params ) ) {
			$url .= ( strpos( $url, '?' ) === false ? '?' : '&' ) . http_build_query( $params );
		}

		$default_args = [
			'headers' => [
				'Accept' => 'application/json',
			],
			'timeout' => 15,
		];

		// Add body parameters for POST requests
		if ( $config['method'] === 'POST' ) {
			$default_args['body'] = $params;
		}

		$args = wp_parse_args( $args, $default_args );

		// Make the request using appropriate method
		$response = $config['method'] === 'POST' ?
			wp_remote_post( $url, $args ) :
			wp_remote_get( $url, $args );

		return $this->handle_response( $response );
	}

	/**
	 * Handle API response
	 *
	 * @param mixed $response API response
	 *
	 * @return array|WP_Error Processed response or WP_Error
	 */
	private function handle_response( $response ) {
		if ( is_wp_error( $response ) ) {
			return new WP_Error(
				'api_error',
				sprintf(
					__( 'IPQualityScore API request failed: %s', 'arraypress' ),
					$response->get_error_message()
				)
			);
		}

		$status_code = wp_remote_retrieve_response_code( $response );
		if ( $status_code !== 200 ) {
			return new WP_Error(
				'api_error',
				sprintf(
					__( 'IPQualityScore API returned error code: %d', 'arraypress' ),
					$status_code
				)
			);
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( json_last_error() !== JSON_ERROR_NONE ) {
			return new WP_Error(
				'json_error',
				__( 'Failed to parse IPQualityScore API response', 'arraypress' )
			);
		}

		if ( isset( $data['errors'] ) ) {
			return new WP_Error(
				'api_error',
				is_array( $data['errors'] ) ? implode( ' ', $data['errors'] ) : $data['errors']
			);
		}

		return $data;
	}

	/**
	 * Check IP reputation against the IPQualityScore API
	 *
	 * @param string $ip                IP address to check.
	 * @param array  $additional_params Optional. Additional parameters for the API request.
	 *                                  Default empty array.
	 *
	 * @return IP|WP_Error IP response object on success, WP_Error on failure.
	 * @since 1.0.0
	 *
	 */
	public function check_ip( string $ip, array $additional_params = [] ) {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return new WP_Error(
				'invalid_ip',
				sprintf( __( 'Invalid IP address: %s', 'arraypress' ), $ip )
			);
		}

		$cache_key = $this->get_cache_key( 'ip_' . $ip . md5( serialize( $additional_params ) ) );

		if ( $this->enable_cache ) {
			$cached_data = get_transient( $cache_key );
			if ( false !== $cached_data ) {
				return new IP( $cached_data );
			}
		}

		$response = $this->make_request( 'ip', [ 'ip' => $ip ] + $additional_params );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		if ( $this->enable_cache ) {
			set_transient( $cache_key, $response, $this->cache_expiration );
		}

		return new IP( $response );
	}

	/**
	 * Validate email address using the IPQualityScore API.
	 *
	 * Checks email validity, deliverability, and potential fraud indicators.
	 *
	 * @param string $email             Email address to validate.
	 * @param array  $additional_params Optional. Additional parameters for the API request.
	 *                                  Default empty array.
	 *
	 * @return Email|WP_Error Email response object on success, WP_Error on failure.
	 * @since 1.0.0
	 *
	 */
	public function validate_email( string $email, array $additional_params = [] ) {
		if ( ! filter_var( $email, FILTER_VALIDATE_EMAIL ) ) {
			return new WP_Error(
				'invalid_email',
				sprintf( __( 'Invalid email format: %s', 'arraypress' ), $email )
			);
		}

		$cache_key = $this->get_cache_key( 'email_' . $email . md5( serialize( $additional_params ) ) );

		if ( $this->enable_cache ) {
			$cached_data = get_transient( $cache_key );
			if ( false !== $cached_data ) {
				return new Email( $cached_data );
			}
		}

		$response = $this->make_request( 'email', [ 'email' => $email ] + $additional_params );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		if ( $this->enable_cache ) {
			set_transient( $cache_key, $response, $this->cache_expiration );
		}

		return new Email( $response );
	}

	/**
	 * Check for leaked data in dark web breaches.
	 *
	 * Searches for compromised data across email addresses, usernames, and passwords.
	 *
	 * @param string $value             Value to check (email, password, or username).
	 * @param string $type              Optional. Type of check ('email', 'password', 'username').
	 *                                  Default 'email'.
	 * @param array  $additional_params Optional. Additional parameters for the API request.
	 *                                  Default empty array.
	 *
	 * @return LeakCheck|WP_Error LeakCheck response object on success, WP_Error on failure.
	 * @since 1.0.0
	 *
	 */
	public function check_leaked_data( string $value, string $type = 'email', array $additional_params = [] ) {
		$valid_types = [ 'email', 'password', 'username' ];

		if ( ! in_array( $type, $valid_types ) ) {
			return new WP_Error(
				'invalid_type',
				sprintf( __( 'Invalid leak check type. Must be one of: %s', 'arraypress' ), implode( ', ', $valid_types ) )
			);
		}

		// Basic validation based on type
		switch ( $type ) {
			case 'email':
				if ( ! filter_var( $value, FILTER_VALIDATE_EMAIL ) ) {
					return new WP_Error( 'invalid_email', __( 'Invalid email format', 'arraypress' ) );
				}
				break;
			case 'password':
			case 'username':
				if ( empty( $value ) ) {
					return new WP_Error( "invalid_{$type}", __( "{$type} cannot be empty", 'arraypress' ) );
				}
				break;
		}

		$cache_key = $this->get_cache_key( "leak_{$type}_{$value}" . md5( serialize( $additional_params ) ) );

		if ( $this->enable_cache ) {
			$cached_data = get_transient( $cache_key );
			if ( false !== $cached_data ) {
				return new LeakCheck( $cached_data );
			}
		}

		$response = $this->make_request( 'leaked', [
			                                           'type'  => $type,
			                                           'value' => $value
		                                           ] + $additional_params );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		if ( $this->enable_cache ) {
			set_transient( $cache_key, $response, $this->cache_expiration );
		}

		return new LeakCheck( $response );
	}

	/**
	 * Scan URL for malicious content using the IPQualityScore API.
	 *
	 * Analyzes URLs for phishing, malware, and other security threats.
	 *
	 * @param string $url               URL to scan for malicious content.
	 * @param array  $additional_params Optional. Additional parameters for the API request.
	 *                                  Default empty array.
	 *
	 * @return URL|WP_Error URL response object on success, WP_Error on failure.
	 * @since 1.0.0
	 *
	 */
	public function scan_url( string $url, array $additional_params = [] ) {
		if ( ! filter_var( $url, FILTER_VALIDATE_URL ) ) {
			return new WP_Error(
				'invalid_url',
				sprintf( __( 'Invalid URL format: %s', 'arraypress' ), $url )
			);
		}

		$cache_key = $this->get_cache_key( 'url_' . $url . md5( serialize( $additional_params ) ) );

		if ( $this->enable_cache ) {
			$cached_data = get_transient( $cache_key );
			if ( false !== $cached_data ) {
				return new URL( $cached_data );
			}
		}

		$response = $this->make_request( 'url', [ 'url' => $url ] + $additional_params );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		if ( $this->enable_cache ) {
			set_transient( $cache_key, $response, $this->cache_expiration );
		}

		return new URL( $response );
	}

	/**
	 * Validate phone number using the IPQualityScore API.
	 *
	 * Validates phone numbers and provides detailed information about their status,
	 * carrier, location, and potential fraud indicators.
	 *
	 * @param string $phone             Phone number to validate.
	 * @param array  $additional_params Optional. Additional parameters for the API request.
	 *                                  Supported parameters include:
	 *                                  - country[] : Array of preferred countries (e.g., ['US', 'UK', 'CA'])
	 *                                  - strictness : Verification strictness level (0-1)
	 *                                  Default empty array.
	 *
	 * @return Phone|WP_Error Phone response object on success, WP_Error on failure.
	 * @since 1.0.0
	 *
	 */
	public function validate_phone( string $phone, array $additional_params = [] ) {
		if ( empty( $phone ) || strlen( $phone ) < 10 ) {
			return new WP_Error(
				'invalid_phone',
				__( 'Phone number must be at least 10 digits long', 'arraypress' )
			);
		}

		// Remove common phone number formatting
		$phone = preg_replace( '/[^0-9]/', '', $phone );

		$cache_key = $this->get_cache_key( 'phone_' . $phone . md5( serialize( $additional_params ) ) );

		if ( $this->enable_cache ) {
			$cached_data = get_transient( $cache_key );
			if ( false !== $cached_data ) {
				return new Phone( $cached_data );
			}
		}

		$response = $this->make_request( 'phone', [ 'phone' => $phone ] + $additional_params );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		if ( $this->enable_cache ) {
			set_transient( $cache_key, $response, $this->cache_expiration );
		}

		return new Phone( $response );
	}

	/**
	 * Validate a transaction against the IPQualityScore API.
	 *
	 * Analyzes transaction details for potential fraud indicators and risk assessment.
	 *
	 * @param array $transaction_data Transaction details to validate. Required fields:
	 *                                - ip_address: IP address of the transaction (required)
	 *                                - user_email: Email address of the user
	 *                                - user_phone: Phone number of the user
	 *                                - transaction_amount: Amount of the transaction
	 *                                - currency: Currency code (e.g., USD)
	 *                                - transaction_type: Type of transaction (purchase, deposit, etc)
	 *
	 * @return Transaction|WP_Error Transaction response object on success, WP_Error on failure.
	 * @since 1.0.0
	 *
	 */
	public function validate_transaction( array $transaction_data ) {
		$required_fields = [ 'ip_address' ];
		foreach ( $required_fields as $field ) {
			if ( ! isset( $transaction_data[ $field ] ) ) {
				return new WP_Error(
					'missing_field',
					sprintf( __( 'Missing required field: %s', 'arraypress' ), $field )
				);
			}
		}

		$response = $this->make_request( 'transaction', $transaction_data );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		return new Transaction( $response );
	}

	/**
	 * Get credit usage information from IPQualityScore API.
	 *
	 * Retrieves detailed information about API credit usage including:
	 * - Total available credits
	 * - Current usage
	 * - Usage by service (proxy, email, phone, URL)
	 * - Remaining credits
	 *
	 * @param array $additional_params Optional. Additional parameters for the API request.
	 *                                 Default empty array.
	 *
	 * @return CreditUsage|WP_Error CreditUsage response object on success, WP_Error on failure.
	 * @since 1.0.0
	 *
	 */
	public function get_credit_usage( array $additional_params = [] ) {
		$cache_key = $this->get_cache_key( 'credit_usage_' . md5( serialize( $additional_params ) ) );

		if ( $this->enable_cache ) {
			$cached_data = get_transient( $cache_key );
			if ( false !== $cached_data ) {
				return new CreditUsage( $cached_data );
			}
		}

		$response = $this->make_request( 'account', $additional_params );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		if ( $this->enable_cache ) {
			// Cache for a shorter time since this is dynamic data
			set_transient( $cache_key, $response, min( 300, $this->cache_expiration ) );
		}

		return new CreditUsage( $response );
	}

	/**
	 * Report fraudulent activity
	 *
	 * @param array $data              Report data containing one of: ip, email, request_id, or phone with country
	 * @param array $additional_params Additional parameters
	 *
	 * @return FraudReport|WP_Error
	 */
	public function report_fraud( array $data, array $additional_params = [] ) {
		// Validate that at least one required parameter is present
		$valid_params = [ 'ip', 'email', 'request_id', 'phone' ];
		$has_required = false;
		foreach ( $valid_params as $param ) {
			if ( isset( $data[ $param ] ) && ! empty( $data[ $param ] ) ) {
				$has_required = true;
				break;
			}
		}

		if ( ! $has_required ) {
			return new WP_Error(
				'missing_parameter',
				__( 'Must provide at least one of: ip, email, request_id, or phone', 'arraypress' )
			);
		}

		// Validate parameters if present
		if ( isset( $data['ip'] ) && ! filter_var( $data['ip'], FILTER_VALIDATE_IP ) ) {
			return new WP_Error(
				'invalid_ip',
				sprintf( __( 'Invalid IP address: %s', 'arraypress' ), $data['ip'] )
			);
		}

		if ( isset( $data['email'] ) && ! filter_var( $data['email'], FILTER_VALIDATE_EMAIL ) ) {
			return new WP_Error(
				'invalid_email',
				sprintf( __( 'Invalid email format: %s', 'arraypress' ), $data['email'] )
			);
		}

		if ( isset( $data['phone'] ) ) {
			// Phone requires country
			if ( ! isset( $data['country'] ) || empty( $data['country'] ) ) {
				return new WP_Error(
					'missing_country',
					__( 'Country is required when reporting a phone number', 'arraypress' )
				);
			}

			// Basic phone number validation
			if ( ! preg_match( '/^\+?[\d\s-]{9,20}$/', $data['phone'] ) ) {
				return new WP_Error(
					'invalid_phone',
					sprintf( __( 'Invalid phone number format: %s', 'arraypress' ), $data['phone'] )
				);
			}

			// Basic country code validation (if 2-letter code provided)
			if ( strlen( $data['country'] ) === 2 && ! preg_match( '/^[A-Z]{2}$/', strtoupper( $data['country'] ) ) ) {
				return new WP_Error(
					'invalid_country',
					sprintf( __( 'Invalid country code: %s', 'arraypress' ), $data['country'] )
				);
			}
		}

		$params   = array_merge( $data, $additional_params );
		$response = $this->make_request( 'report', $params );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		return new FraudReport( $response );
	}

	/**
	 * Report a fraudulent IP address
	 *
	 * @param string $ip                IP address to report
	 * @param array  $additional_params Additional parameters
	 *
	 * @return FraudReport|WP_Error
	 */
	public function report_ip( string $ip, array $additional_params = [] ) {
		return $this->report_fraud( [ 'ip' => $ip ], $additional_params );
	}

	/**
	 * Report a fraudulent email address
	 *
	 * @param string $email             Email to report
	 * @param array  $additional_params Additional parameters
	 *
	 * @return FraudReport|WP_Error
	 */
	public function report_email( string $email, array $additional_params = [] ) {
		return $this->report_fraud( [ 'email' => $email ], $additional_params );
	}

	/**
	 * Report a fraudulent phone number
	 *
	 * @param string $phone             Phone number to report
	 * @param string $country           Two-letter country code or full country name
	 * @param array  $additional_params Additional parameters
	 *
	 * @return FraudReport|WP_Error
	 */
	public function report_phone( string $phone, string $country, array $additional_params = [] ) {
		return $this->report_fraud( [
			'phone'   => $phone,
			'country' => $country
		], $additional_params );
	}

	/**
	 * Report a previous request as fraudulent
	 *
	 * @param string $request_id        Request ID to report
	 * @param array  $additional_params Additional parameters
	 *
	 * @return FraudReport|WP_Error
	 */
	public function report_request( string $request_id, array $additional_params = [] ) {
		return $this->report_fraud( [ 'request_id' => $request_id ], $additional_params );
	}


	/**
	 * Get list of previous API requests
	 *
	 * @param string $type              Type of requests to retrieve ('proxy', 'email', 'devicetracker',
	 *                                  'mobiletracker')
	 * @param array  $additional_params Additional parameters:
	 *                                  - start_date: Start date (YYYY-MM-DD)
	 *                                  - stop_date: End date (YYYY-MM-DD)
	 *                                  - ip_address: Filter by IP address
	 *                                  - device_id: Filter by Device ID (device fingerprinting only)
	 *                                  - page: Page number for pagination
	 *                                  + any custom tracking variables set in account
	 *
	 * @return RequestList|WP_Error
	 */
	public function get_request_list( string $type, array $additional_params = [] ) {
		// Validate request type
		$valid_types = [ 'proxy', 'email', 'devicetracker', 'mobiletracker' ];
		if ( ! in_array( $type, $valid_types ) ) {
			return new WP_Error(
				'invalid_type',
				sprintf( __( 'Invalid request type. Must be one of: %s', 'arraypress' ),
					implode( ', ', $valid_types ) )
			);
		}

		// Validate dates if provided
		foreach ( [ 'start_date', 'stop_date' ] as $date_field ) {
			if ( isset( $additional_params[ $date_field ] ) ) {
				$date = \DateTime::createFromFormat( 'Y-m-d', $additional_params[ $date_field ] );
				if ( ! $date || $date->format( 'Y-m-d' ) !== $additional_params[ $date_field ] ) {
					return new WP_Error(
						'invalid_date',
						sprintf( __( 'Invalid date format for %s. Use YYYY-MM-DD', 'arraypress' ),
							$date_field )
					);
				}
			}
		}

		// Validate IP if provided
		if ( isset( $additional_params['ip_address'] ) &&
		     ! filter_var( $additional_params['ip_address'], FILTER_VALIDATE_IP ) ) {
			return new WP_Error(
				'invalid_ip',
				sprintf( __( 'Invalid IP address: %s', 'arraypress' ),
					$additional_params['ip_address'] )
			);
		}

		$params = array_merge( [ 'type' => $type ], $additional_params );

		$cache_key = $this->get_cache_key( 'request_list_' .
		                                   $type . '_' . md5( serialize( $additional_params ) ) );

		if ( $this->enable_cache ) {
			$cached_data = get_transient( $cache_key );
			if ( false !== $cached_data ) {
				return new RequestList( $cached_data );
			}
		}

		$response = $this->make_request( 'requests/list', $params );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		if ( $this->enable_cache ) {
			// Cache for a shorter time since this is historical data
			set_transient( $cache_key, $response, min( 300, $this->cache_expiration ) );
		}

		return new RequestList( $response );
	}

	/**
	 * Get list of countries and their codes
	 *
	 * Note: This endpoint doesn't require an API key and is rate-limited to once per 5 seconds.
	 *
	 * @param bool $raw Whether to get the raw format instead of JSON
	 *
	 * @return CountryList|string|WP_Error Returns CountryListResponse for JSON format,
	 *                                            string for raw format, or WP_Error on failure
	 */
	public function get_country_list( bool $raw = false ) {
		// Use a different cache key for each format
		$cache_key = $this->get_cache_key( 'countries_' . ( $raw ? 'raw' : 'json' ) );

		if ( $this->enable_cache ) {
			$cached_data = get_transient( $cache_key );
			if ( false !== $cached_data ) {
				return $raw ? $cached_data : new CountryList( $cached_data );
			}
		}

		// Different URL structure for country list API
		$url = 'https://www.ipqualityscore.com/api/countries/' . ( $raw ? 'raw' : 'json' );

		$args = [
			'headers' => [
				'Accept' => $raw ? 'text/plain' : 'application/json',
			],
			'timeout' => 15,
		];

		$response = wp_remote_get( $url, $args );

		if ( is_wp_error( $response ) ) {
			return new WP_Error(
				'api_error',
				sprintf(
					__( 'Country list request failed: %s', 'arraypress' ),
					$response->get_error_message()
				)
			);
		}

		$status_code = wp_remote_retrieve_response_code( $response );
		if ( $status_code !== 200 ) {
			return new WP_Error(
				'api_error',
				sprintf(
					__( 'Country list API returned error code: %d', 'arraypress' ),
					$status_code
				)
			);
		}

		$body = wp_remote_retrieve_body( $response );

		if ( $raw ) {
			if ( $this->enable_cache ) {
				// Cache for 24 hours since this rarely changes
				set_transient( $cache_key, $body, DAY_IN_SECONDS );
			}

			return $body;
		}

		$data = json_decode( $body, true );

		if ( json_last_error() !== JSON_ERROR_NONE ) {
			return new WP_Error(
				'json_error',
				__( 'Failed to parse country list response', 'arraypress' )
			);
		}

		if ( $this->enable_cache ) {
			// Cache for 24 hours since this rarely changes
			set_transient( $cache_key, $data, DAY_IN_SECONDS );
		}

		return new CountryList( $data );
	}


	/**
	 * Create an allowlist entry
	 *
	 * @param string      $value      Value to allowlist
	 * @param string      $type       Type of API (proxy, url, email, phone, mobiletracker, devicetracker)
	 * @param string      $value_type Type of value (ip, cidr, email, etc.)
	 * @param string|null $reason     Optional reason for allowlisting
	 *
	 * @return EntryList|WP_Error
	 */
	public function create_allowlist_entry(
		string $value,
		string $type,
		string $value_type,
		?string $reason = null
	) {
		// Validate type
		if ( ! isset( self::ALLOWLIST_TYPES[ $type ] ) ) {
			return new WP_Error(
				'invalid_type',
				sprintf(
					__( 'Invalid allowlist type. Must be one of: %s', 'arraypress' ),
					implode( ', ', array_keys( self::ALLOWLIST_TYPES ) )
				)
			);
		}

		// Validate value_type
		if ( $type !== 'custom' && ! in_array( $value_type, self::ALLOWLIST_TYPES[ $type ] ) ) {
			return new WP_Error(
				'invalid_value_type',
				sprintf(
					__( 'Invalid value type for %s. Must be one of: %s', 'arraypress' ),
					$type,
					implode( ', ', self::ALLOWLIST_TYPES[ $type ] )
				)
			);
		}

		// Validate value format based on value_type
		if ( ! $this->validate_allowlist_value( $value, $value_type ) ) {
			return new WP_Error(
				'invalid_value',
				sprintf( __( 'Invalid format for value type: %s', 'arraypress' ), $value_type )
			);
		}

		$params = [
			'value'      => $value,
			'type'       => $type,
			'value_type' => $value_type
		];

		if ( $reason !== null ) {
			$params['reason'] = $reason;
		}

		$response = $this->make_request( 'allowlist/create', $params );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		return new EntryList( $response );
	}

	/**
	 * Get list of allowlist entries
	 *
	 * @return EntryList|WP_Error
	 */
	public function get_allowlist_entries() {
		$response = $this->make_request( 'allowlist/list' );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		return new EntryList( $response );
	}

	/**
	 * Delete an allowlist entry
	 *
	 * @param string $value      Value to remove
	 * @param string $type       Type of API
	 * @param string $value_type Type of value
	 *
	 * @return EntryList|WP_Error
	 */
	public function delete_allowlist_entry(
		string $value,
		string $type,
		string $value_type
	) {
		// Validate type and value_type same as create
		if ( ! isset( self::ALLOWLIST_TYPES[ $type ] ) ) {
			return new WP_Error(
				'invalid_type',
				sprintf(
					__( 'Invalid allowlist type. Must be one of: %s', 'arraypress' ),
					implode( ', ', array_keys( self::ALLOWLIST_TYPES ) )
				)
			);
		}

		if ( $type !== 'custom' && ! in_array( $value_type, self::ALLOWLIST_TYPES[ $type ] ) ) {
			return new WP_Error(
				'invalid_value_type',
				sprintf(
					__( 'Invalid value type for %s. Must be one of: %s', 'arraypress' ),
					$type,
					implode( ', ', self::ALLOWLIST_TYPES[ $type ] )
				)
			);
		}

		$params = [
			'value'      => $value,
			'type'       => $type,
			'value_type' => $value_type
		];

		$response = $this->make_request( 'allowlist/delete', $params );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		return new EntryList( $response );
	}

	/**
	 * Validate allowlist value format
	 *
	 * @param string $value      Value to validate
	 * @param string $value_type Type of value
	 *
	 * @return bool
	 */
	private function validate_allowlist_value( string $value, string $value_type ): bool {
		switch ( $value_type ) {
			case 'ip':
				return filter_var( $value, FILTER_VALIDATE_IP ) !== false;
			case 'cidr':
				if ( strpos( $value, '/' ) === false ) {
					return false;
				}
				list( $ip, $mask ) = explode( '/', $value );

				return filter_var( $ip, FILTER_VALIDATE_IP ) !== false &&
				       is_numeric( $mask ) &&
				       $mask >= 0 &&
				       $mask <= 32;
			case 'email':
				return filter_var( $value, FILTER_VALIDATE_EMAIL ) !== false;
			case 'domain':
				return filter_var( $value, FILTER_VALIDATE_DOMAIN ) !== false;
			case 'phone':
				return preg_match( '/^\+?[\d\s-]{9,20}$/', $value ) === 1;
			case 'isp':
			case 'deviceid':
				return ! empty( $value );
			default:
				return true; // Custom value types are always valid
		}
	}

	/**
	 * Create a blocklist entry
	 *
	 * @param string      $value      Value to blocklist
	 * @param string      $type       Type of API (proxy, url, email, phone, mobiletracker, devicetracker)
	 * @param string      $value_type Type of value (ip, cidr, email, etc.)
	 * @param string|null $reason     Optional reason for blocklisting
	 *
	 * @return EntryList|WP_Error
	 */
	public function create_blocklist_entry(
		string $value,
		string $type,
		string $value_type,
		?string $reason = null
	) {
		// Use same validation as allowlist since types are identical
		if ( ! isset( self::ALLOWLIST_TYPES[ $type ] ) ) {
			return new WP_Error(
				'invalid_type',
				sprintf(
					__( 'Invalid blocklist type. Must be one of: %s', 'arraypress' ),
					implode( ', ', array_keys( self::ALLOWLIST_TYPES ) )
				)
			);
		}

		if ( $type !== 'custom' && ! in_array( $value_type, self::ALLOWLIST_TYPES[ $type ] ) ) {
			return new WP_Error(
				'invalid_value_type',
				sprintf(
					__( 'Invalid value type for %s. Must be one of: %s', 'arraypress' ),
					$type,
					implode( ', ', self::ALLOWLIST_TYPES[ $type ] )
				)
			);
		}

		// Validate value format based on value_type
		if ( ! $this->validate_allowlist_value( $value, $value_type ) ) {
			return new WP_Error(
				'invalid_value',
				sprintf( __( 'Invalid format for value type: %s', 'arraypress' ), $value_type )
			);
		}

		$params = [
			'value'      => $value,
			'type'       => $type,
			'value_type' => $value_type
		];

		if ( $reason !== null ) {
			$params['reason'] = $reason;
		}

		$response = $this->make_request( 'blocklist/create', $params );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		return new EntryList( $response );
	}

	/**
	 * Get list of blocklist entries
	 *
	 * @return EntryList|WP_Error
	 */
	public function get_blocklist_entries() {
		$response = $this->make_request( 'blocklist/list' );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		return new EntryList( $response );
	}

	/**
	 * Delete a blocklist entry
	 *
	 * @param string $value      Value to remove
	 * @param string $type       Type of API
	 * @param string $value_type Type of value
	 *
	 * @return EntryList|WP_Error
	 */
	public function delete_blocklist_entry(
		string $value,
		string $type,
		string $value_type
	) {
		// Validate type and value_type same as create
		if ( ! isset( self::ALLOWLIST_TYPES[ $type ] ) ) {
			return new WP_Error(
				'invalid_type',
				sprintf(
					__( 'Invalid blocklist type. Must be one of: %s', 'arraypress' ),
					implode( ', ', array_keys( self::ALLOWLIST_TYPES ) )
				)
			);
		}

		if ( $type !== 'custom' && ! in_array( $value_type, self::ALLOWLIST_TYPES[ $type ] ) ) {
			return new WP_Error(
				'invalid_value_type',
				sprintf(
					__( 'Invalid value type for %s. Must be one of: %s', 'arraypress' ),
					$type,
					implode( ', ', self::ALLOWLIST_TYPES[ $type ] )
				)
			);
		}

		$params = [
			'value'      => $value,
			'type'       => $type,
			'value_type' => $value_type
		];

		$response = $this->make_request( 'blocklist/delete', $params );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		return new EntryList( $response );
	}

	/**
	 * Generate cache key
	 *
	 * @param string $identifier Unique identifier
	 *
	 * @return string Cache key
	 */
	private function get_cache_key( string $identifier ): string {
		return 'ipqs_' . md5( $identifier . $this->api_key );
	}

	/**
	 * Clear cached data
	 *
	 * @param string|null $identifier Optional specific identifier to clear
	 *
	 * @return bool Success status
	 */
	public function clear_cache( ?string $identifier = null ): bool {
		if ( $identifier !== null ) {
			return delete_transient( $this->get_cache_key( $identifier ) );
		}

		global $wpdb;
		$pattern = $wpdb->esc_like( '_transient_ipqs_' ) . '%';

		return $wpdb->query(
				$wpdb->prepare(
					"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s",
					$pattern
				)
			) !== false;
	}

}