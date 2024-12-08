<?php

declare( strict_types=1 );

namespace ArrayPress\IPQualityScore\Response;

/**
 * Leak Check Response Class
 *
 * Represents a response from the IPQualityScore Leak Check API.
 * Based on the official IPQualityScore Dark Web Leak API documentation.
 */
class LeakCheck extends Base {

	/**
	 * Check if any data was exposed in leaks
	 *
	 * @return bool
	 */
	public function is_exposed(): bool {
		return $this->data['exposed'] ?? false;
	}

	/**
	 * Get array of sources where the data was found
	 *
	 * @return array
	 */
	public function get_sources(): array {
		return $this->data['source'] ?? [];
	}

	/**
	 * Get first seen information
	 *
	 * @return array|null Returns array with 'human', 'timestamp', and 'iso' keys, or null if not available
	 */
	public function get_first_seen(): ?array {
		if ( ! isset( $this->data['first_seen'] ) ) {
			return null;
		}

		return $this->data['first_seen'];
	}

	/**
	 * Get human-readable first seen date
	 *
	 * @return string|null
	 */
	public function get_first_seen_human(): ?string {
		return $this->data['first_seen']['human'] ?? null;
	}

	/**
	 * Get first seen timestamp
	 *
	 * @return int|null
	 */
	public function get_first_seen_timestamp(): ?int {
		return isset( $this->data['first_seen']['timestamp'] )
			? (int) $this->data['first_seen']['timestamp']
			: null;
	}

	/**
	 * Get first seen ISO date
	 *
	 * @return string|null
	 */
	public function get_first_seen_iso(): ?string {
		return $this->data['first_seen']['iso'] ?? null;
	}

	/**
	 * Check if plain text password was found
	 *
	 * @return bool
	 */
	public function has_plain_text_password(): bool {
		return $this->data['plain_text_password'] ?? false;
	}

	/**
	 * Get the message from the API response
	 *
	 * @return string|null
	 */
	public function get_message(): ?string {
		return $this->data['message'] ?? null;
	}

}