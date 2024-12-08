<?php

declare( strict_types=1 );

namespace ArrayPress\IPQualityScore;

/**
 * Transaction Builder Class
 * Complete implementation with all available parameters from the documentation
 */
class Transaction {

	private array $data = [];

	/**
	 * Set required IP address information
	 *
	 * @param string $ip_address IP address to analyze
	 *
	 * @return self
	 */
	public function set_ip_address( string $ip_address ): self {
		$this->data['ip_address'] = $ip_address;

		return $this;
	}

	/**
	 * Set user context information
	 *
	 * @param array $context User context information
	 *
	 * @return self
	 */
	public function set_user_context( array $context ): self {
		$allowed_fields = [
			'user_agent',
			'language',
			'username',
			'user_email',
			'password_hash',
			'user_phone',
			'user_fingerprint'
		];

		foreach ( $allowed_fields as $field ) {
			if ( isset( $context[ $field ] ) ) {
				$this->data[ $field ] = $context[ $field ];
			}
		}

		// Additional user account data
		if ( isset( $context['account_creation_date'] ) ) {
			$this->data['account_creation_date'] = $context['account_creation_date'];
		}
		if ( isset( $context['last_login'] ) ) {
			$this->data['last_login'] = $context['last_login'];
		}
		if ( isset( $context['total_logins'] ) ) {
			$this->data['total_logins'] = $context['total_logins'];
		}

		return $this;
	}

	/**
	 * Set billing information
	 *
	 * @param array $billing Billing details
	 *
	 * @return self
	 */
	public function set_billing( array $billing ): self {
		$allowed_fields = [
			'first_name',
			'last_name',
			'company',
			'email',
			'phone',
			'address1',
			'address2',
			'city',
			'region',
			'country',
			'zipcode',
			'region_code',
			'country_code'
		];

		foreach ( $allowed_fields as $field ) {
			if ( isset( $billing[ $field ] ) ) {
				$this->data[ 'billing_' . $field ] = $billing[ $field ];
			}
		}

		return $this;
	}

	/**
	 * Set shipping information
	 *
	 * @param array $shipping Shipping details
	 *
	 * @return self
	 */
	public function set_shipping( array $shipping ): self {
		$allowed_fields = [
			'first_name',
			'last_name',
			'company',
			'email',
			'phone',
			'address1',
			'address2',
			'city',
			'region',
			'country',
			'zipcode',
			'region_code',
			'country_code'
		];

		foreach ( $allowed_fields as $field ) {
			if ( isset( $shipping[ $field ] ) ) {
				$this->data[ 'shipping_' . $field ] = $shipping[ $field ];
			}
		}

		return $this;
	}

	/**
	 * Set payment information
	 *
	 * @param array $payment Payment information
	 *
	 * @return self
	 */
	public function set_payment( array $payment ): self {
		// Credit card information
		if ( isset( $payment['card'] ) ) {
			$allowed_card_fields = [
				'bin',
				'last4',
				'expiry_month',
				'expiry_year',
				'card_hash',
				'avs_code',
				'cvv_code'
			];

			foreach ( $allowed_card_fields as $field ) {
				if ( isset( $payment['card'][ $field ] ) ) {
					$this->data[ 'credit_card_' . $field ] = $payment['card'][ $field ];
				}
			}
		}

		// Transaction information
		$allowed_transaction_fields = [
			'amount',
			'currency',
			'time',
			'gateway',
			'payment_method'
		];

		foreach ( $allowed_transaction_fields as $field ) {
			if ( isset( $payment[ $field ] ) ) {
				$this->data[ 'transaction_' . $field ] = $payment[ $field ];
			}
		}

		return $this;
	}

	/**
	 * Set order information
	 *
	 * @param array $order Order details
	 *
	 * @return self
	 */
	public function set_order( array $order ): self {
		$allowed_fields = [
			'order_id',
			'transaction_id',
			'affiliate_id',
			'subaffiliate_id',
			'source',
			'referrer',
			'product_sku',
			'product_name',
			'product_url',
			'product_category',
			'quantity',
			'has_digital_goods',
			'has_physical_goods',
			'shipping_method',
			'shipping_speed',
			'recurring_order',
			'recurring_order_count',
			'gift_order'
		];

		foreach ( $allowed_fields as $field ) {
			if ( isset( $order[ $field ] ) ) {
				$this->data[ $field ] = $order[ $field ];
			}
		}

		return $this;
	}

	/**
	 * Set customer information
	 *
	 * @param array $customer Customer details
	 *
	 * @return self
	 */
	public function set_customer( array $customer ): self {
		$allowed_fields = [
			'customer_id',
			'is_guest',
			'has_note',
			'loyalty_level',
			'total_orders',
			'total_spent',
			'first_order_date',
			'first_seen',
			'last_seen',
			'previous_purchases'
		];

		foreach ( $allowed_fields as $field ) {
			if ( isset( $customer[ $field ] ) ) {
				$this->data[ $field ] = $customer[ $field ];
			}
		}

		return $this;
	}

	/**
	 * Set device fingerprint
	 *
	 * @param string $fingerprint Device fingerprint token
	 *
	 * @return self
	 */
	public function set_device_fingerprint( string $fingerprint ): self {
		$this->data['device_fingerprint'] = $fingerprint;

		return $this;
	}

	/**
	 * Set merchant information
	 *
	 * @param array $merchant Merchant details
	 *
	 * @return self
	 */
	public function set_merchant( array $merchant ): self {
		$allowed_fields = [
			'store_id',
			'store_name',
			'store_domain',
			'business_name',
			'business_domain',
			'business_type',
			'business_id'
		];

		foreach ( $allowed_fields as $field ) {
			if ( isset( $merchant[ $field ] ) ) {
				$this->data[ $field ] = $merchant[ $field ];
			}
		}

		return $this;
	}

	/**
	 * Add risk scoring options
	 *
	 * @param array $options Risk scoring options
	 *
	 * @return self
	 */
	public function set_scoring_options( array $options ): self {
		$allowed_fields = [
			'strictness',
			'fast',
			'lighter_penalties',
			'allow_public_access_points'
		];

		foreach ( $allowed_fields as $field ) {
			if ( isset( $options[ $field ] ) ) {
				$this->data[ $field ] = $options[ $field ];
			}
		}

		return $this;
	}

	/**
	 * Add custom variables
	 *
	 * @param array $variables Custom variables
	 *
	 * @return self
	 */
	public function add_variables( array $variables ): self {
		foreach ( $variables as $key => $value ) {
			$this->data['variables'][ $key ] = $value;
		}

		return $this;
	}

	/**
	 * Get the built transaction data
	 *
	 * @return array
	 */
	public function get_data(): array {
		return $this->data;
	}

}