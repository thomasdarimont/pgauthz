package authz

import "context"

// StoreStat is a per-store metrics sample (ADR 0010, Slice 3).
type StoreStat struct {
	Store  string
	Tuples int64
}

// StoreStatser samples engine/tenant stats for periodic metrics gauges.
// Implemented by the direct pgx backend.
type StoreStatser interface {
	// StoreStats returns the top `limit` stores by tuple count plus the total
	// number of stores.
	StoreStats(ctx context.Context, limit int) (stats []StoreStat, storesTotal int64, err error)
}
