<?php

declare( strict_types=1 );

namespace ArrayPress\IPQualityScore\Response;

/**
 * Email Response Class
 *
 * Represents a response from the IPQualityScore Email Verification API.
 * Based on the official API documentation.
 */
class Email extends Base {

	/**
	 * Check if email is valid
	 *
	 * @return bool
	 */
	public function is_valid(): bool {
		return $this->data['valid'] ?? false;
	}

	/**
	 * Check if the request timed out
	 *
	 * @return bool
	 */
	public function is_timed_out(): bool {
		return $this->data['timed_out'] ?? false;
	}

	/**
	 * Check if email is disposable
	 *
	 * @return bool
	 */
	public function is_disposable(): bool {
		return $this->data['disposable'] ?? false;
	}

	/**
	 * Get first name from email if available
	 *
	 * @return string|null
	 */
	public function get_first_name(): ?string {
		return $this->data['first_name'] ?? null;
	}

	/**
	 * Get email deliverability status
	 *
	 * @return string|null
	 */
	public function get_deliverability(): ?string {
		return $this->data['deliverability'] ?? null;
	}

	/**
	 * Get SMTP score
	 *
	 * @return int|null
	 */
	public function get_smtp_score(): ?int {
		return isset( $this->data['smtp_score'] ) ? (int) $this->data['smtp_score'] : null;
	}

	/**
	 * Get overall score
	 *
	 * @return int|null
	 */
	public function get_overall_score(): ?int {
		return isset( $this->data['overall_score'] ) ? (int) $this->data['overall_score'] : null;
	}

	/**
	 * Check if this is a catch-all email domain
	 *
	 * @return bool
	 */
	public function is_catch_all(): bool {
		return $this->data['catch_all'] ?? false;
	}

	/**
	 * Check if email is generic
	 *
	 * @return bool
	 */
	public function is_generic(): bool {
		return $this->data['generic'] ?? false;
	}

	/**
	 * Check if email is common
	 *
	 * @return bool
	 */
	public function is_common(): bool {
		return $this->data['common'] ?? false;
	}

	/**
	 * Check if DNS is valid
	 *
	 * @return bool
	 */
	public function is_dns_valid(): bool {
		return $this->data['dns_valid'] ?? false;
	}

	/**
	 * Check if honeypot
	 *
	 * @return bool
	 */
	public function is_honeypot(): bool {
		return $this->data['honeypot'] ?? false;
	}

	/**
	 * Check if frequent complainer
	 *
	 * @return bool
	 */
	public function is_frequent_complainer(): bool {
		return $this->data['frequent_complainer'] ?? false;
	}

	/**
	 * Check if suspect
	 *
	 * @return bool
	 */
	public function is_suspect(): bool {
		return $this->data['suspect'] ?? false;
	}

	/**
	 * Check if recent abuse detected
	 *
	 * @return bool
	 */
	public function has_recent_abuse(): bool {
		return $this->data['recent_abuse'] ?? false;
	}

	/**
	 * Get the fraud score
	 *
	 * @return int|null
	 */
	public function get_fraud_score(): ?int {
		return isset( $this->data['fraud_score'] ) ? (int) $this->data['fraud_score'] : null;
	}

	/**
	 * Check if email was found in data leaks
	 *
	 * @return bool
	 */
	public function is_leaked(): bool {
		return $this->data['leaked'] ?? false;
	}

	/**
	 * Get suggested domain if any
	 *
	 * @return string|null
	 */
	public function get_suggested_domain(): ?string {
		return $this->data['suggested_domain'] ?? null;
	}

	/**
	 * Get domain velocity
	 *
	 * @return string|null
	 */
	public function get_domain_velocity(): ?string {
		return $this->data['domain_velocity'] ?? null;
	}

	/**
	 * Get domain trust level
	 *
	 * @return string|null
	 */
	public function get_domain_trust(): ?string {
		return $this->data['domain_trust'] ?? null;
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
	 * Get associated names data
	 *
	 * @return array
	 */
	public function get_associated_names(): array {
		return $this->data['associated_names'] ?? [];
	}

	/**
	 * Get associated phone numbers data
	 *
	 * @return array
	 */
	public function get_associated_phone_numbers(): array {
		return $this->data['associated_phone_numbers'] ?? [];
	}

	/**
	 * Get first seen information
	 *
	 * @return array|null Returns array with 'human', 'timestamp', and 'iso' keys
	 */
	public function get_first_seen(): ?array {
		return $this->data['first_seen'] ?? null;
	}

	/**
	 * Get domain age information
	 *
	 * @return array|null Returns array with 'human', 'timestamp', and 'iso' keys
	 */
	public function get_domain_age(): ?array {
		return $this->data['domain_age'] ?? null;
	}

	/**
	 * Get spam trap score
	 *
	 * @return string|null
	 */
	public function get_spam_trap_score(): ?string {
		return $this->data['spam_trap_score'] ?? null;
	}

	/**
	 * Check if domain uses risky TLD
	 *
	 * @return bool
	 */
	public function has_risky_tld(): bool {
		return $this->data['risky_tld'] ?? false;
	}

	/**
	 * Check if domain has SPF record
	 *
	 * @return bool
	 */
	public function has_spf_record(): bool {
		return $this->data['spf_record'] ?? false;
	}

	/**
	 * Check if domain has DMARC record
	 *
	 * @return bool
	 */
	public function has_dmarc_record(): bool {
		return $this->data['dmarc_record'] ?? false;
	}

	/**
	 * Get sanitized email address
	 *
	 * @return string|null
	 */
	public function get_sanitized_email(): ?string {
		return $this->data['sanitized_email'] ?? null;
	}

	/**
	 * Get MX records
	 *
	 * @return array
	 */
	public function get_mx_records(): array {
		return $this->data['mx_records'] ?? [];
	}

	/**
	 * Get A records
	 *
	 * @return array
	 */
	public function get_a_records(): array {
		return $this->data['a_records'] ?? [];
	}

}