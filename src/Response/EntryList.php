<?php

declare( strict_types=1 );

namespace ArrayPress\IPQualityScore\Response;

/**
 * Blocklist Response Class
 */
class EntryList extends Base {

	/**
	 * Get blocklist entries
	 *
	 * @return array
	 */
	public function get_entries(): array {
		return $this->data['data'] ?? [];
	}

	/**
	 * Get entries of a specific type
	 *
	 * @param string $type Entry type (proxy, url, email, phone, etc.)
	 *
	 * @return array
	 */
	public function get_entries_by_type( string $type ): array {
		return array_filter( $this->get_entries(), function ( $entry ) use ( $type ) {
			return ( $entry['type'] ?? '' ) === $type;
		} );
	}

	/**
	 * Get entries of a specific value type
	 *
	 * @param string $value_type Value type (ip, cidr, email, etc.)
	 *
	 * @return array
	 */
	public function get_entries_by_value_type( string $value_type ): array {
		return array_filter( $this->get_entries(), function ( $entry ) use ( $value_type ) {
			return ( $entry['value_type'] ?? '' ) === $value_type;
		} );
	}

	/**
	 * Find entry by value
	 *
	 * @param string $value Value to find
	 *
	 * @return array|null Entry data or null if not found
	 */
	public function find_entry( string $value ): ?array {
		foreach ( $this->get_entries() as $entry ) {
			if ( ( $entry['value'] ?? '' ) === $value ) {
				return $entry;
			}
		}

		return null;
	}

}