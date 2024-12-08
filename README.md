# IPQualityScore Library for WordPress

A WordPress library for IPQualityScore API integration providing proxy & VPN detection, email validation, phone verification, dark web monitoring, URL scanning, and fraud prevention with WordPress transient caching.

## Installation

Install via Composer:

```bash
composer require arraypress/ipqualityscore
```

## Requirements

- PHP 7.4 or later
- WordPress 6.2.2 or later
- IPQualityScore API key

## Basic Usage

```php
use ArrayPress\IPQualityScore\Client;

// Initialize with your API key
$client = new Client( 'your-api-key-here' );

// Check IP address
$response = $client->check_ip( '1.1.1.1' );

// Validate email
$response = $client->validate_email( 'test@example.com' );

// Validate phone number
$response = $client->validate_phone( '18007132618', [ 'country' => 'US' ] );

// Check for leaked data
$response = $client->check_leaked_data( 'test@example.com', 'email' );

// Scan URL
$response = $client->scan_url( 'https://example.com' );
```

## Available Methods

### Client Methods

```php
// Initialize client with options
$client = new Client(
    'your-api-key-here',   // API key
    true,                  // Enable caching (optional, default: true)
    3600                   // Cache duration in seconds (optional, default: 3600)
);

// Set common options
$client->set_strictness( 1 );                    // Set strictness level (0-3)
$client->set_allow_public_access_points( true ); // Allow public access points
$client->set_lighter_penalties( true );          // Use lighter penalties

// IP Reputation Check
$ip_check = $client->check_ip( '1.1.1.1' );

// Email Validation
$email_check = $client->validate_email( 'test@example.com' );

// Phone Validation
$phone_check = $client->validate_phone( '18007132618', [ 'country' => 'US' ] );

// Dark Web Leak Check
$leak_check = $client->check_leaked_data( 'test@example.com', 'email' );

// URL Scanning
$url_scan = $client->scan_url( 'https://example.com' );

// Transaction Validation
$transaction = $client->validate_transaction( [
    'ip_address' => '1.1.1.1',
    // Additional transaction data
] );

// Allow & Block Lists
$client->create_allowlist_entry( '1.1.1.1', 'proxy', 'ip', 'Trusted IP') ;
$entries = $client->get_allowlist_entries();
$client->delete_allowlist_entry( '1.1.1.1', 'proxy', 'ip' );

$client->create_blocklist_entry( '8.8.8.8', 'proxy', 'ip', 'Malicious IP' );
$entries = $client->get_blocklist_entries();
$client->delete_blocklist_entry( '8.8.8.8', 'proxy', 'ip' );

// Request History
$requests = $client->get_request_list ('proxy', [
    'start_date' => '2024-01-01',
    'stop_date' => '2024-01-31'
] );

// Credit Usage
$credits = $client->get_credit_usage();

// Cache Management
$client->clear_cache();                 // Clear all cached data
$client->clear_cache( 'ip_1.1.1.1' );    // Clear specific cache
```

### IP Response Methods

```php
// Basic checks
$is_proxy = $response->is_proxy();
$is_vpn = $response->is_vpn();
$is_tor = $response->is_tor();
$is_crawler = $response->is_crawler();

// Scores and risk assessment
$fraud_score = $response->get_fraud_score();
$abuse_velocity = $response->get_abuse_velocity();
$recent_abuse = $response->has_recent_abuse();

// Connection info
$connection_type = $response->get_connection_type();
$is_mobile = $response->is_mobile();
$is_bot = $response->is_bot();

// Location data
$country = $response->get_country_code();
$region = $response->get_region();
$city = $response->get_city();
$timezone = $response->get_timezone();

// Network info
$organization = $response->get_organization();
$asn = $response->get_asn();
$host = $response->get_host();
```

### Email Response Methods

```php
$is_valid = $response->is_valid();
$is_disposable = $response->is_disposable();
$smtp_score = $response->get_smtp_score();
$overall_score = $response->get_overall_score();
$is_deliverable = $response->get_deliverability();
$first_name = $response->get_first_name();
$domain_age = $response->get_domain_age();
$fraud_score = $response->get_fraud_score();
$suggested_domain = $response->get_suggested_domain();
$leaked = $response->is_leaked();
```

### Phone Response Methods

```php
$is_valid = $response->is_valid();
$fraud_score = $response->get_fraud_score();
$formatted = $response->get_formatted();
$carrier = $response->get_carrier();
$line_type = $response->get_line_type();
$is_active = $response->is_active();
$is_risky = $response->is_risky();
$leaked = $response->is_leaked();
```

### URL Response Methods

```php
$is_unsafe = $response->is_unsafe();
$domain_age = $response->get_domain_age();
$risk_score = $response->get_risk_score();
$is_phishing = $response->is_phishing();
$is_malware = $response->is_malware();
$category = $response->get_category();
$dns_valid = $response->is_dns_valid();
$risk_factors = $response->get_risk_factors();
```

## Response Examples

### IP Check Response

```php
[
    "success" => true,
    "message" => "Success",
    "fraud_score" => 25,
    "country_code" => "US",
    "region" => "California",
    "city" => "Los Angeles",
    "ISP" => "Cloudflare, Inc.",
    "ASN" => 13335,
    "organization" => "Cloudflare, Inc.",
    "is_crawler" => false,
    "timezone" => "America/Los_Angeles",
    "mobile" => false,
    "host" => "one.one.one.one",
    "proxy" => true,
    "vpn" => true,
    "tor" => false,
    "recent_abuse" => false,
    "bot_status" => false
]
```

### Email Response

```php
[
    "success" => true,
    "valid" => true,
    "disposable" => false,
    "smtp_score" => 3,
    "overall_score" => 4,
    "first_name" => "John",
    "deliverability" => "high",
    "dns_valid" => true,
    "fraud_score" => 25,
    "leaked" => false,
    "suggested_domain" => "example.com",
    "domain_velocity" => "high",
    "domain_trust" => "trusted",
    "request_id" => "..."
]
```

## Error Handling

The library uses WordPress's `WP_Error` for error handling:

```php
$response = $client->check_ip( 'invalid-ip' );

if ( is_wp_error( $response ) ) {
    echo $response->get_error_message();
    // Output: "Invalid IP address: invalid-ip"
}
```

Common error cases:
- Invalid input formats (IP, email, phone, URL)
- Invalid API key
- API request failures
- Insufficient credits
- Invalid responses

## Additional Features

### Allow & Block Lists
Manage trusted and blocked entities:
```php
// Allowlist
$client->create_allowlist_entry( '1.1.1.1', 'proxy', 'ip' );
$client->get_allowlist_entries();
$client->delete_allowlist_entry( '1.1.1.1', 'proxy', 'ip' );

// Blocklist
$client->create_blocklist_entry( '8.8.8.8', 'proxy', 'ip' );
$client->get_blocklist_entries();
$client->delete_blocklist_entry( '8.8.8.8', 'proxy', 'ip' );
```

### Credit Usage Monitoring
Track API usage:
```php
$credits = $client->get_credit_usage();
echo "Available credits: " . $credits->get_credits();
echo "Usage this period: " . $credits->get_usage();
```

## Contributions

Contributions to this library are highly appreciated. Raise issues on GitHub or submit pull requests for bug fixes or new features. Share feedback and suggestions for improvements.

## License: GPLv2 or later

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.