// Package store exposes persistence interfaces for identity keys, pre-keys,
// signed pre-keys, and session data. Stores must enforce freshness policies
// such as signed pre-key expiry and session limits.
package store
