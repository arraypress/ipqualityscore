<?php

declare( strict_types=1 );

namespace ArrayPress\IPQualityScore\Response;

/**
 * Credit Usage Response Class
 *
 * Represents a response from the IPQualityScore Credit Usage API.
 */
class CreditUsage extends Base {

	/**
	 * Get total available credits
	 *
	 * @return int|null
	 */
	public function get_credits(): ?int {
		return isset( $this->data['credits'] ) ? (int) $this->data['credits'] : null;
	}

	/**
	 * Get total usage for the current billing period
	 *
	 * @return int|null
	 */
	public function get_usage(): ?int {
		return isset( $this->data['usage'] ) ? (int) $this->data['usage'] : null;
	}

	/**
	 * Get proxy detection API usage
	 *
	 * @return int|null
	 */
	public function get_proxy_usage(): ?int {
		return isset( $this->data['proxy_usage'] ) ? (int) $this->data['proxy_usage'] : null;
	}

	/**
	 * Get email validation API usage
	 *
	 * @return int|null
	 */
	public function get_email_usage(): ?int {
		return isset( $this->data['email_usage'] ) ? (int) $this->data['email_usage'] : null;
	}

	/**
	 * Get Mobile SDK usage
	 *
	 * @return int|null
	 */
	public function get_mobile_sdk_usage(): ?int {
		return isset( $this->data['mobile_sdk_usage'] ) ? (int) $this->data['mobile_sdk_usage'] : null;
	}

	/**
	 * Get phone validation API usage
	 *
	 * @return int|null
	 */
	public function get_phone_usage(): ?int {
		return isset( $this->data['phone_usage'] ) ? (int) $this->data['phone_usage'] : null;
	}

	/**
	 * Get URL scanning API usage
	 *
	 * @return int|null
	 */
	public function get_url_usage(): ?int {
		return isset( $this->data['url_usage'] ) ? (int) $this->data['url_usage'] : null;
	}

	/**
	 * Get fingerprint API usage
	 *
	 * @return int|null
	 */
	public function get_fingerprint_usage(): ?int {
		return isset( $this->data['fingerprint_usage'] ) ? (int) $this->data['fingerprint_usage'] : null;
	}

	/**
	 * Get remaining credits
	 *
	 * @return int|null
	 */
	public function get_remaining_credits(): ?int {
		$credits = $this->get_credits();
		$usage   = $this->get_usage();

		if ( $credits === null || $usage === null ) {
			return null;
		}

		return max( 0, $credits - $usage );
	}

	/**
	 * Get usage percentage
	 *
	 * @return float|null Percentage of credits used (0-100)
	 */
	public function get_usage_percentage(): ?float {
		$credits = $this->get_credits();
		$usage   = $this->get_usage();

		if ( $credits === null || $usage === null || $credits === 0 ) {
			return null;
		}

		return round( ( $usage / $credits ) * 100, 2 );
	}

}