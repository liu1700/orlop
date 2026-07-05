// Package dataclient is a Go client for the orlop data plane (orlop-server).
//
// Where the sibling package client speaks the control-plane REST API (allocate
// disks, mint enroll tokens), dataclient speaks the binary, mTLS, msgpack frame
// protocol of orlop-server directly, to perform whole-file operations — list,
// stat, read, write, delete, rename — on one agent's disk subtree.
//
// It needs no FUSE mount and takes no mount lease: reads are lease-free, and
// writes are guarded by manifest compare-and-swap (see WriteFile and ErrStale),
// so a caller can browse and mutate an agent's files whether or not the agent
// itself is running. Isolation is the agent-scoped mTLS certificate obtained
// from Enroll: orlop-server confines the connection to that one agent's subtree.
//
// Typical flow:
//
//	creds, err := dataclient.Enroll(ctx, nil, controlURL, enrollToken)
//	c, err := dataclient.Dial(ctx, creds)
//	defer c.Close()
//	entries, err := c.ListDir(ctx, "/")
//	data, info, err := c.ReadFile(ctx, "/notes.txt")
//	v, err := c.WriteFile(ctx, "/notes.txt", newData, info.Version, dataclient.WriteOpts{})
//
// A Client serializes requests on its single connection (one op in flight at a
// time); construct several Clients for concurrency. The wire structs and frame
// codec are reused from orlop-server so the encoding is byte-identical.
package dataclient
