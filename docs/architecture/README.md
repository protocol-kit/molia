# Architecture

This directory contains documentation on Molia's core architectural patterns and design principles.

## Documents

### [Shared-Nothing Architecture](shared-nothing-architecture.md)
Defines how state is partitioned across per-core shards with zero shared mutable memory. Covers:
- XOR-local shard selection (`msb_k(selfId XOR key)`)
- Per-shard event loops and core affinity
- Cross-shard messaging with QoS classes (Control, Coordination, Hints)
- Lock-free communication via SPSC/MPSC rings
- Backpressure and drop policies
- Iterative lookup execution within shards

**Key Insight**: Complete isolation enables scalability without contention; each shard is an independent micro-service pinned to a CPU core.

### [Zero-Allocation Design](zero-allocation-design.md)
Specifies strategies to eliminate heap allocations on hot paths. Covers:
- Buffer pools and bump arenas
- Fixed-capacity containers (`ArrayVec`, `SmallVec`)
- Zero-copy codec integration
- Batch I/O with recycled buffers
- Verification via allocation-counting tests

**Key Insight**: Predictable performance and minimal GC pressure through disciplined memory management.

---

## Relationship

These two documents are complementary:
- **Shared-Nothing** describes *how* work is partitioned and isolated
- **Zero-Allocation** describes *how* each shard manages memory efficiently

Together they form the foundation for Molia's performance and scalability characteristics.

---

[← Back to Documentation](../README.md)

