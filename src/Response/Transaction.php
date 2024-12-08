<?php

declare( strict_types=1 );

namespace ArrayPress\IPQualityScore\Response;

/**
 * Transaction Response Class
 */
class Transaction extends Base {

	/**
	 * Get the risk score
	 *
	 * @return int|null
	 */
	public function get_risk_score(): ?int {
		return isset( $this->data['risk_score'] ) ? (int) $this->data['risk_score'] : null;
	}

	/**
	 * Get transaction risk factors
	 *
	 * @return array
	 */
	public function get_risk_factors(): array {
		return $this->data['risk_factors'] ?? [];
	}

	/**
	 * Check if proxy
	 *
	 * @return bool
	 */
	public function is_proxy(): bool {
		return $this->data['proxy'] ?? false;
	}

	/**
	 * Check if high risk
	 *
	 * @return bool
	 */
	public function is_high_risk(): bool {
		return $this->data['high_risk'] ?? false;
	}

	/**
	 * Get transaction confidence score
	 *
	 * @return float|null
	 */
	public function get_confidence_score(): ?float {
		return isset( $this->data['confidence_score'] ) ? (float) $this->data['confidence_score'] : null;
	}

	/**
	 * Get transaction status
	 *
	 * @return string|null
	 */
	public function get_status(): ?string {
		return $this->data['status'] ?? null;
	}

	/**
	 * Get country match status
	 *
	 * @return bool
	 */
	public function is_country_match(): bool {
		return $this->data['country_match'] ?? false;
	}

	/**
	 * Check if risky billing address
	 *
	 * @return bool
	 */
	public function has_risky_billing_address(): bool {
		return $this->data['risky_billing_address'] ?? false;
	}

	/**
	 * Check if risky shipping address
	 *
	 * @return bool
	 */
	public function has_risky_shipping_address(): bool {
		return $this->data['risky_shipping_address'] ?? false;
	}

	/**
	 * Get transaction features array
	 *
	 * @return array
	 */
	public function get_transaction_features(): array {
		return $this->data['transaction_features'] ?? [];
	}

	/**
	 * Get bin details if available
	 *
	 * @return array|null
	 */
	public function get_bin_details(): ?array {
		return $this->data['bin_details'] ?? null;
	}

	/**
	 * Get fraud score
	 *
	 * @return int|null
	 */
	public function get_fraud_score(): ?int {
		return isset( $this->data['fraud_score'] ) ? (int) $this->data['fraud_score'] : null;
	}

	/**
	 * Get payment risk score
	 *
	 * @return int|null
	 */
	public function get_payment_risk_score(): ?int {
		return isset( $this->data['payment_risk_score'] ) ? (int) $this->data['payment_risk_score'] : null;
	}

	/**
	 * Get risk factors description
	 *
	 * @return array
	 */
	public function get_risk_factors_description(): array {
		return $this->data['risk_factors_description'] ?? [];
	}

}