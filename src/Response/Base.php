<?php

declare( strict_types=1 );

namespace ArrayPress\IPQualityScore\Response;

/**
 * Base Response Class
 */
abstract class Base {

	/**
	 * Raw response data
	 *
	 * @var array
	 */
	protected array $data;

	/**
	 * Initialize response
	 *
	 * @param array $data Raw response data
	 */
	public function __construct( array $data ) {
		$this->data = $data;
	}

	/**
	 * Get raw data array
	 *
	 * @return array
	 */
	public function get_raw_data(): array {
		return $this->data;
	}

	/**
	 * Get success status
	 *
	 * @return bool
	 */
	public function is_success(): bool {
		return $this->data['success'] ?? false;
	}

	/**
	 * Get request ID
	 *
	 * @return string|null
	 */
	public function get_request_id(): ?string {
		return $this->data['request_id'] ?? null;
	}

	/**
	 * Get message if any
	 *
	 * @return string|null
	 */
	public function get_message(): ?string {
		return $this->data['message'] ?? null;
	}

	/**
	 * Get errors if any
	 *
	 * @return array
	 */
	public function get_errors(): array {
		return $this->data['errors'] ?? [];
	}

	/**
	 * Magic method to get raw data values
	 *
	 * @param string $name Property name
	 *
	 * @return mixed|null
	 */
	public function __get( string $name ) {
		return $this->data[ $name ] ?? null;
	}

	/**
	 * Magic method to check if raw data value exists
	 *
	 * @param string $name Property name
	 *
	 * @return bool
	 */
	public function __isset( string $name ): bool {
		return isset( $this->data[ $name ] );
	}

}