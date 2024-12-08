<?php

declare( strict_types=1 );

namespace ArrayPress\IPQualityScore\Response;

/**
 * Request List Response Class
 *
 * Represents a response from the IPQualityScore Request List API.
 */
class RequestList extends Base {

	/**
	 * Get the array of request records
	 *
	 * @return array
	 */
	public function get_requests(): array {
		return $this->data['requests'] ?? [];
	}

	/**
	 * Get current page number
	 *
	 * @return int
	 */
	public function get_current_page(): int {
		return $this->data['current_page'] ?? 1;
	}

	/**
	 * Get total number of pages
	 *
	 * @return int
	 */
	public function get_total_pages(): int {
		return $this->data['total_pages'] ?? 0;
	}

	/**
	 * Get number of requests on current page
	 *
	 * @return int
	 */
	public function get_request_count(): int {
		return $this->data['request_count'] ?? 0;
	}

	/**
	 * Get maximum records per page
	 *
	 * @return int
	 */
	public function get_max_records_per_page(): int {
		return $this->data['max_records_per_page'] ?? 25;
	}

	/**
	 * Get total number of records
	 *
	 * @return int
	 */
	public function get_total_records(): int {
		return $this->data['total_records'] ?? 0;
	}

	/**
	 * Check if there are more pages
	 *
	 * @return bool
	 */
	public function has_next_page(): bool {
		return $this->get_current_page() < $this->get_total_pages();
	}

	/**
	 * Get requests of a specific type
	 *
	 * @param string $type Request type to filter (proxy, email, devicetracker, mobiletracker)
	 *
	 * @return array
	 */
	public function get_requests_by_type( string $type ): array {
		return array_filter( $this->get_requests(), function ( $request ) use ( $type ) {
			return ( $request['type'] ?? '' ) === $type;
		} );
	}

	/**
	 * Get request details by request ID
	 *
	 * @param string $request_id Request ID to find
	 *
	 * @return array|null Request details or null if not found
	 */
	public function get_request_by_id( string $request_id ): ?array {
		foreach ( $this->get_requests() as $request ) {
			if ( ( $request['request_id'] ?? '' ) === $request_id ) {
				return $request;
			}
		}

		return null;
	}

}