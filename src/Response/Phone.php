<?php

declare( strict_types=1 );

namespace ArrayPress\IPQualityScore\Response;

/**
 * Phone Response Class
 *
 * Represents a response from the IPQualityScore Phone Number Validation API.
 */
class Phone extends Base {

	/**
	 * Check if phone number is valid
	 *
	 * @return bool
	 */
	public function is_valid(): bool {
		return $this->data['valid'] ?? false;
	}

	/**
	 * Get formatted phone number with country code
	 *
	 * @return string|null
	 */
	public function get_formatted(): ?string {
		return $this->data['formatted'] !== 'N/A' ? $this->data['formatted'] : null;
	}

	/**
	 * Get locally formatted phone number
	 *
	 * @return string|null
	 */
	public function get_local_format(): ?string {
		return $this->data['local_format'] !== 'N/A' ? $this->data['local_format'] : null;
	}

	/**
	 * Get fraud score
	 *
	 * @return int|null
	 */
	public function get_fraud_score(): ?int {
		return isset($this->data['fraud_score']) ? (int)$this->data['fraud_score'] : null;
	}

	/**
	 * Check if number has recent abuse
	 *
	 * @return bool|null
	 */
	public function has_recent_abuse(): ?bool {
		return $this->data['recent_abuse'] ?? null;
	}

	/**
	 * Check if number is VOIP
	 *
	 * @return bool|null
	 */
	public function is_voip(): ?bool {
		return $this->data['VOIP'] ?? null;
	}

	/**
	 * Check if number is prepaid
	 *
	 * @return bool|null
	 */
	public function is_prepaid(): ?bool {
		return $this->data['prepaid'] ?? null;
	}

	/**
	 * Check if number is risky
	 *
	 * @return bool|null
	 */
	public function is_risky(): ?bool {
		return $this->data['risky'] ?? null;
	}

	/**
	 * Check if number is active
	 *
	 * @return bool|null
	 */
	public function is_active(): ?bool {
		return $this->data['active'] ?? null;
	}

	/**
	 * Get owner name if available
	 *
	 * @return string|null
	 */
	public function get_name(): ?string {
		return $this->data['name'] !== 'N/A' ? $this->data['name'] : null;
	}

	/**
	 * Get carrier name
	 *
	 * @return string|null
	 */
	public function get_carrier(): ?string {
		return $this->data['carrier'] !== 'N/A' ? $this->data['carrier'] : null;
	}

	/**
	 * Get line type
	 *
	 * @return string|null
	 */
	public function get_line_type(): ?string {
		return $this->data['line_type'] ?? null;
	}

	/**
	 * Get country code
	 *
	 * @return string|null
	 */
	public function get_country(): ?string {
		return $this->data['country'] !== 'N/A' ? $this->data['country'] : null;
	}

	/**
	 * Get region/state
	 *
	 * @return string|null
	 */
	public function get_region(): ?string {
		return $this->data['region'] !== 'N/A' ? $this->data['region'] : null;
	}

	/**
	 * Get city
	 *
	 * @return string|null
	 */
	public function get_city(): ?string {
		return $this->data['city'] !== 'N/A' ? $this->data['city'] : null;
	}

	/**
	 * Get timezone
	 *
	 * @return string|null
	 */
	public function get_timezone(): ?string {
		return $this->data['timezone'] !== 'N/A' ? $this->data['timezone'] : null;
	}

	/**
	 * Get zip code
	 *
	 * @return string|null
	 */
	public function get_zip_code(): ?string {
		return $this->data['zip_code'] !== 'N/A' ? $this->data['zip_code'] : null;
	}

	/**
	 * Check if country code is accurate
	 *
	 * @return bool
	 */
	public function has_accurate_country_code(): bool {
		return $this->data['accurate_country_code'] ?? false;
	}

	/**
	 * Get dialing code
	 *
	 * @return int|null
	 */
	public function get_dialing_code(): ?int {
		return isset($this->data['dialing_code']) ? (int)$this->data['dialing_code'] : null;
	}

	/**
	 * Check if number is on do not call list
	 *
	 * @return bool|null
	 */
	public function is_do_not_call(): ?bool {
		return $this->data['do_not_call'] ?? null;
	}

	/**
	 * Check if number has been leaked
	 *
	 * @return bool|null
	 */
	public function is_leaked(): ?bool {
		return $this->data['leaked'] ?? null;
	}

	/**
	 * Check if number is associated with spam
	 *
	 * @return bool|null
	 */
	public function is_spammer(): ?bool {
		return $this->data['spammer'] ?? null;
	}

	/**
	 * Get active status description
	 *
	 * @return string|null
	 */
	public function get_active_status(): ?string {
		return $this->data['active_status'] ?? null;
	}

	/**
	 * Get user activity level
	 *
	 * @return string|null
	 */
	public function get_user_activity(): ?string {
		return $this->data['user_activity'] ?? null;
	}

	/**
	 * Get associated email addresses
	 *
	 * @return array
	 */
	public function get_associated_email_addresses(): array {
		if (!isset($this->data['associated_email_addresses'])) {
			return [];
		}
		return $this->data['associated_email_addresses']['emails'] ?? [];
	}

	/**
	 * Get Mobile Network Code
	 *
	 * @return string|null
	 */
	public function get_mnc(): ?string {
		return $this->data['mnc'] !== 'N/A' ? $this->data['mnc'] : null;
	}

	/**
	 * Get Mobile Country Code
	 *
	 * @return string|null
	 */
	public function get_mcc(): ?string {
		return $this->data['mcc'] !== 'N/A' ? $this->data['mcc'] : null;
	}

}