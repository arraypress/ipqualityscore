<?php

declare( strict_types=1 );

namespace ArrayPress\IPQualityScore\Response;

/**
 * Country List Response Class
 *
 * Represents a response from the IPQualityScore Country List API.
 */
class CountryList extends Base {

	/**
	 * Get all countries as code => name array
	 *
	 * @return array
	 */
	public function get_countries(): array {
		return $this->data['countries'] ?? [];
	}

	/**
	 * Get country name by country code
	 *
	 * @param string $code Country code (2 characters)
	 *
	 * @return string|null Country name or null if not found
	 */
	public function get_country_name( string $code ): ?string {
		$code = strtoupper( $code );

		return $this->data['countries'][ $code ] ?? null;
	}

	/**
	 * Get country code by country name
	 *
	 * @param string $name Country name
	 *
	 * @return string|null Country code or null if not found
	 */
	public function get_country_code( string $name ): ?string {
		$countries = array_flip( $this->get_countries() );

		return $countries[ $name ] ?? null;
	}

	/**
	 * Check if a country code exists
	 *
	 * @param string $code Country code
	 *
	 * @return bool
	 */
	public function has_country_code( string $code ): bool {
		$code = strtoupper( $code );

		return isset( $this->data['countries'][ $code ] );
	}

	/**
	 * Check if a country name exists
	 *
	 * @param string $name Country name
	 *
	 * @return bool
	 */
	public function has_country_name( string $name ): bool {
		return in_array( $name, $this->get_countries(), true );
	}

	/**
	 * Get list of country codes
	 *
	 * @return array
	 */
	public function get_country_codes(): array {
		return array_keys( $this->get_countries() );
	}

	/**
	 * Get list of country names
	 *
	 * @return array
	 */
	public function get_country_names(): array {
		return array_values( $this->get_countries() );
	}

	/**
	 * Get number of countries
	 *
	 * @return int
	 */
	public function count(): int {
		return count( $this->get_countries() );
	}

}