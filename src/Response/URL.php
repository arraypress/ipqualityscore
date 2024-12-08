<?php

declare( strict_types=1 );

namespace ArrayPress\IPQualityScore\Response;

/**
 * URL Scanning Response Class
 */
class URL extends Base {

	/**
	 * Check if URL is unsafe
	 *
	 * @return bool
	 */
	public function is_unsafe(): bool {
		return $this->data['unsafe'] ?? false;
	}

	/**
	 * Get the domain age in days
	 *
	 * @return int|null
	 */
	public function get_domain_age(): ?int {
		return isset( $this->data['domain_age']['days'] ) ? (int) $this->data['domain_age']['days'] : null;
	}

	/**
	 * Get server details
	 *
	 * @return array|null
	 */
	public function get_server_details(): ?array {
		return $this->data['server'] ?? null;
	}

	/**
	 * Get the risk score
	 *
	 * @return int|null
	 */
	public function get_risk_score(): ?int {
		return isset( $this->data['risk_score'] ) ? (int) $this->data['risk_score'] : null;
	}

	/**
	 * Check if domain is suspicious
	 *
	 * @return bool
	 */
	public function is_suspicious(): bool {
		return $this->data['suspicious'] ?? false;
	}

	/**
	 * Check if phishing detected
	 *
	 * @return bool
	 */
	public function is_phishing(): bool {
		return $this->data['phishing'] ?? false;
	}

	/**
	 * Check if malware detected
	 *
	 * @return bool
	 */
	public function is_malware(): bool {
		return $this->data['malware'] ?? false;
	}

	/**
	 * Check if parking/spamming domain
	 *
	 * @return bool
	 */
	public function is_parking(): bool {
		return $this->data['parking'] ?? false;
	}

	/**
	 * Check if spamming domain
	 *
	 * @return bool
	 */
	public function is_spamming(): bool {
		return $this->data['spamming'] ?? false;
	}

	/**
	 * Get category name
	 *
	 * @return string|null
	 */
	public function get_category(): ?string {
		return $this->data['category'] ?? null;
	}

	/**
	 * Get domain rank
	 *
	 * @return int|null
	 */
	public function get_domain_rank(): ?int {
		return isset( $this->data['domain_rank'] ) ? (int) $this->data['domain_rank'] : null;
	}

	/**
	 * Get DNS valid status
	 *
	 * @return bool
	 */
	public function is_dns_valid(): bool {
		return $this->data['dns_valid'] ?? false;
	}

	/**
	 * Get suspicious factors
	 *
	 * @return array
	 */
	public function get_risk_factors(): array {
		return $this->data['risk_factors'] ?? [];
	}

	/**
	 * Get redirected URL if any
	 *
	 * @return string|null
	 */
	public function get_redirected_url(): ?string {
		return $this->data['redirected_url'] ?? null;
	}

	/**
	 * Get final destination URL
	 *
	 * @return string|null
	 */
	public function get_final_url(): ?string {
		return $this->data['final_url'] ?? null;
	}

	/**
	 * Get content type
	 *
	 * @return string|null
	 */
	public function get_content_type(): ?string {
		return $this->data['content_type'] ?? null;
	}

	/**
	 * Get status code
	 *
	 * @return int|null
	 */
	public function get_status_code(): ?int {
		return isset( $this->data['status_code'] ) ? (int) $this->data['status_code'] : null;
	}

}
