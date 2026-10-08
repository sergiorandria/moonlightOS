# MoonlightOS Project Roadmap

## Executive Summary

This roadmap outlines the strategic direction for MoonlightOS development over the next 6-12 months, focusing on:
1. **Completed**: IPC improvements (message IDs, synchronization, queue capacity, flow control)
2. **In Progress**: SOLID principles refactoring for code quality
3. **Planned**: CAP theorem compliance for reliability and distributed readiness

---

## Current Status

### ✅ Completed (2026-10-04)
- **IPC Improvements**:
  - Message IDs for reliable request-response matching
  - Shared memory synchronization with spinlocks
  - Increased IPC queue capacity (16 → 32)
  - Flow control notifications
  - All changes verified and tested

### 🔄 In Progress
- **SOLID Analysis**: Architecture review completed
- **CAP Analysis**: Compliance profile identified (CA)

### 📋 Planned
- **SOLID Refactoring**: 5 sprints over 10 weeks
- **CAP Compliance**: 4 phases over 8 sprints

---

## Strategic Goals

### Goal 1: Code Quality & Maintainability
- Reduce kernel monolith (kboot.c: 2500+ lines → <500 lines)
- Enable modular service development
- Improve test coverage to >80%
- Reduce service addition time from 2 days → 2 hours

### Goal 2: Reliability & Availability
- Add fault tolerance mechanisms
- Implement service health monitoring
- Add timeout and recovery features
- Achieve >99.9% service uptime

### Goal 3: Distributed Readiness
- Design for multi-node clusters
- Implement partition detection
- Add distributed primitives
- Support flexible CAP profiles

### Goal 4: Security Verification
- Maintain Isabelle/HOL proof coverage
- Add new proof obligations for refactored code
- Preserve security guarantees
- Pass all verification gates

---

## Roadmap Timeline

## Phase 1: Foundation (Weeks 1-4)

### Week 1-2: IPC Improvements Integration
**Status**: ✅ Completed

**Deliverables:**
- ✅ Message ID implementation
- ✅ Shared memory spinlocks
- ✅ Queue capacity increase
- ✅ Flow control notifications
- ✅ Documentation (IPC_IMPROVEMENTS.md)
- ✅ Verification pass

**Next Steps:**
- Deploy to production
- Monitor performance impact
- Gather feedback from service developers

### Week 3-4: SOLID Sprint 1 - Kernel Modularization
**Status**: ✅ Landed (branch `feature/solid-sprint1-kernel-modularization`)

**Result:** kboot.c split 2720 → ~695 lines, orchestration only; new
`kernel/kinternal.h` (shared decls) + `device.c` (virtio/GUI discovery) +
`sched.c` (thread table/policy) + `syscall.c` (trap dispatch) +
`elf_loader.c` (spawn factor). Kernel rebuilds `-Werror`-clean, no
duplicate symbols, QEMU transcript identical except the shell `sp=` debug
detail (dropped; layout-dependent, no gate). Two verify.sh smoke gates
(`Services: mem+console+tty+gui up`, `[sched] exited 7`) are stale
pre-existing drift, fail identically before/after.

**Sprint 1b follow-up (production-ready, landed same branch):** finished
the module map per `kernel/kernel.h` + seL4 `src/object` precedent —
`console.c` (SBI/log/timer), `vm.c` (tables/pool/PTE-sync/COW), `sched_tick`
→ `sched.c`, `irq_trap` → `irq.c`, trap dispatch split by operation class
into `syscall_ipc/cap/mem/proc/qube.c`, V2 ABI block → `kinternal.h`.
Final: kboot.c 141, all 16 S-mode TUs ≤ 500 lines; `verify.sh` gains a
module-budget gate and the two vacuous smoke gates were fixed/retired
(Services string updated to the actual boot message; `exited 7` removed —
klog is silenced at boot-complete so it can never print).

**Objective:** Split kboot.c into focused modules

**Tasks:**
1. Create `kernel/syscall.c` - Syscall dispatch
   - Move syscall case statements
   - Implement syscall registration
   - Add syscall versioning

2. Create `kernel/sched.c` - Scheduling
   - Move scheduler logic
   - Implement pluggable policies
   - Add statistics

3. Create `kernel/device.c` - Device management
   - Move virtio initialization
   - Implement device registry
   - Add lifecycle management

4. Create `kernel/elf_loader.c` - ELF loading
   - Move ELF loader
   - Add initrd management
   - Implement verification pipeline

5. Refactor `kboot.c` to orchestration
   - Reduce to <500 lines
   - Coordinate module init
   - Maintain verification

**Success Criteria:**
- kboot.c < 500 lines
- All modules < 500 lines
- Isabelle proofs pass
- No performance regression

---

## Phase 2: Architecture (Weeks 5-8)

### Week 5-6: SOLID Sprint 2 - Dynamic Service Registration
**Status**: 📋 Planned

**Objective:** Enable runtime service discovery

**Tasks:**
1. Implement service registry
   - Service descriptor structure
   - Registration syscall
   - Name-based lookup

2. Add dynamic endpoint allocation
   - Remove hard-coded EP mapping
   - Endpoint-to-service table
   - Support service migration

3. Refactor existing services
   - Update to use registry
   - Remove magic numbers
   - Add capability descriptors

4. Add service discovery API
   - Query by name
   - Query by capability
   - List all services

**Success Criteria:**
- Services addable without kernel rebuild
- Backward compatible
- Verification pass

### Week 7-8: SOLID Sprint 3 - IPC Protocol Modularization
**Status**: 📋 Planned

**Objective:** Split monolithic IPC protocol

**Tasks:**
1. Create service-specific protocol headers
   - `services/gui_protocol.h`
   - `services/console_protocol.h`
   - `services/tty_protocol.h`
   - `services/app_protocol.h`

2. Implement message type registry
   - Message descriptor structure
   - Registration API
   - Runtime validation

3. Refactor IPC helpers
   - Type-safe construction
   - Automatic marshaling
   - Error handling

4. Update all services
   - Use specific headers
   - Register message types
   - Test compatibility

**Success Criteria:**
- Services only include needed protocols
- Message type extensibility
- No regression

---

## Phase 3: Abstraction (Weeks 9-12)

### Week 9-10: SOLID Sprint 4 - Service Interface Abstraction
**Status**: 📋 Planned

**Objective:** Define service interfaces for polymorphism

**Tasks:**
1. Define service interface
   - Standard operations (send/recv/query/control)
   - Interface versioning
   - Capability requirements

2. Implement service proxy
   - Generic wrapper
   - IPC marshaling
   - Error handling

3. Create service factories
   - Instantiate by interface
   - Mock implementations
   - Service composition

4. Refactor services
   - Use interfaces
   - Remove direct dependencies
   - Add mocks for testing

**Success Criteria:**
- Services depend on interfaces
- Mock implementations work
- Test coverage >80%

### Week 11-12: SOLID Sprint 5 - Capability Enhancement
**Status**: 📋 Planned

**Objective:** Improve capability-based dependency management

**Tasks:**
1. Implement capability namespaces
   - Per-service spaces
   - Cross-service grants
   - Inheritance

2. Add capability introspection
   - Query permissions
   - Validate chains
   - Audit usage

3. Implement capability brokers
   - Service-specific management
   - Dynamic allocation
   - Revocation policies

4. Update security model
   - New verification obligations
   - Update Isabelle proofs
   - Security audit

**Success Criteria:**
- Flexible permission management
- Better isolation
- Proofs pass

---

## Phase 4: Reliability (Weeks 13-16)

### Week 13-14: CAP Phase 1 - CA Improvements
**Status**: 📋 Planned

**Objective:** Enhance reliability while maintaining CA profile

**Tasks:**
1. Add IPC timeouts
   - Timeout constants
   - Timeout syscalls
   - Error handling

2. Implement service health monitoring
   - Health structure
   - Heartbeat mechanism
   - Status reporting

3. Add service restart
   - Kernel watchdog
   - Automatic restart
   - State checkpointing

4. Implement async queuing
   - Non-blocking variants
   - Per-service queues
   - Flow control

**Success Criteria:**
- Improved availability
- Better fault tolerance
- Minimal consistency impact

### Week 15-16: CAP Phase 2 - Partition Detection
**Status**: 📋 Planned

**Objective:** Detect and handle component failures

**Tasks:**
1. Implement heartbeat
   - Periodic messages
   - Timeout detection
   - Quarantine mechanism

2. Add partition metadata
   - Track state
   - Maintain history
   - Expose to services

3. Implement degraded mode
   - Reduced functionality
   - Local-only operations
   - Queue for later

4. Add partition recovery
   - Reconciliation
   - State sync
   - Notification

**Success Criteria:**
- Partition detection <1s
- Recovery <10s
- Graceful degradation

---

## Phase 5: Distributed Foundation (Weeks 17-24)

### Week 17-20: CAP Phase 3 - Distributed Architecture
**Status**: 📋 Planned

**Objective:** Design for multi-node clusters

**Tasks:**
1. Design distributed architecture
   - Multi-kernel clusters
   - Distributed qubes
   - Network-aware IPC

2. Implement network IPC
   - Network transport layer
   - Serialization
   - Routing

3. Add distributed locks
   - Lock manager service
   - Lock acquisition/release
   - Deadlock detection

4. Implement distributed transactions
   - Transaction coordinator
   - Two-phase commit
   - Rollback mechanism

**Success Criteria:**
- Design document
- Prototype implementation
- Performance benchmarks

### Week 21-24: CAP Phase 4 - CAP Profile Tuning
**Status**: 📋 Planned

**Objective:** Support flexible CAP profiles per service

**Tasks:**
1. Implement per-service profiles
   - Profile selection API
   - Runtime tuning
   - Profile migration

2. Add tunable consistency
   - Strong/weak consistency
   - Read/write concerns
   - Quorum configuration

3. Implement hybrid profiles
   - Mix consistency levels
   - Dynamic adjustment
   - Monitoring

4. Add reporting
   - Profile metrics
   - CAP violations
   - Performance data

**Success Criteria:**
- Flexible CAP profiles
- Profile switching works
- Monitoring in place

---

## Milestones

### Milestone 1: IPC Improvements (✅ Q4 2026)
- ✅ Message IDs implemented
- ✅ Synchronization added
- ✅ Queue capacity increased
- ✅ Flow control implemented
- ✅ All verified

### Milestone 2: SOLID Sprint 1-2 (📋 Q1 2027)
- Kernel modularized
- Dynamic service registration
- Code quality improved

### Milestone 3: SOLID Sprint 3-5 (📋 Q2 2027)
- IPC protocol modularized
- Service interfaces defined
- Capability system enhanced

### Milestone 4: CAP Phase 1-2 (📋 Q3 2027)
- CA profile improved
- Partition detection added
- Reliability enhanced

### Milestone 5: CAP Phase 3-4 (📋 Q4 2027)
- Distributed architecture designed
- CAP profiles implemented
- Multi-node prototype

---

## Resource Requirements

### Development Team
- 2-3 kernel developers
- 1 verification engineer (Isabelle/HOL)
- 1 QA engineer
- 1 technical writer

### Infrastructure
- CI/CD pipeline
- Verification cluster (Isabelle)
- Test hardware (RISC-V boards)
- QEMU test farm

### Tools
- RISC-V toolchain
- Isabelle/HOL 2025-2
- Performance profilers
- Verification tools

---

## Risk Management

### Risk 1: Breaking Isabelle Proofs
**Probability:** Medium
**Impact:** High
**Mitigation:**
- Incremental proof updates
- Parallel verification branch
- Formal verification sprints
- Proof gates before merge

### Risk 2: Performance Regression
**Probability:** Medium
**Impact:** Medium
**Mitigation:**
- Benchmarking at each phase
- Performance gates
- Optimization sprints
- Profiling tools

### Risk 3: Service Compatibility
**Probability:** Low
**Impact:** Medium
**Mitigation:**
- Backward compatibility layer
- Gradual migration
- Version negotiation
- Migration tools

### Risk 4: Resource Constraints
**Probability:** Medium
**Impact:** Medium
**Mitigation:**
- Prioritize critical path
- Resource leveling
- External review for verification
- Extend timeline if needed

---

## Success Metrics

### Code Quality
- kboot.c: 2500+ → <500 lines
- Module size: <500 lines each
- Cyclomatic complexity: <10 per function
- Test coverage: >80%

### Performance
- IPC latency: <10% increase
- Throughput: <5% decrease
- Memory: <10% overhead
- CPU: <5% overhead

### Reliability
- MTBF: >1000 hours
- MTTR: <5 minutes
- Service uptime: >99.9%
- Kernel uptime: >99.99%

### Verification
- Isabelle proofs: 100% pass
- Anti-vacuity: 100% pass
- Unit tests: 100% pass
- Integration tests: 100% pass

---

## Documentation Deliverables

### Completed
- ✅ IPC_IMPROVEMENTS.md
- ✅ SOLID_ANALYSIS.md
- ✅ CAP_ANALYSIS.md
- ✅ ROADMAP.md (this document)

### In Progress
- 📋 API documentation
- 📋 Architecture documentation
- 📋 Security model documentation
- 📋 Verification guide

---

## Next Steps

### Immediate (This Week)
1. Review and approve roadmap
2. Set up project tracking
3. Allocate resources
4. Begin SOLID Sprint 1 planning

### Short-term (Next 4 Weeks)
1. Execute SOLID Sprint 1
2. Implement kernel modularization
3. Run verification gates
4. Gather feedback

### Medium-term (Next 12 Weeks)
1. Complete SOLID sprints 2-5
2. Begin CAP Phase 1
3. Implement reliability features
4. Update documentation

### Long-term (Next 24 Weeks)
1. Complete CAP phases 2-4
2. Design distributed architecture
3. Implement multi-node prototype
4. Production deployment planning

---

## Conclusion

This roadmap provides a clear path forward for MoonlightOS development, balancing code quality (SOLID), reliability (CAP), and the project's verification-first philosophy. The phased approach minimizes risk while delivering incremental value.

The IPC improvements completed in Phase 1 provide immediate benefits and set the foundation for the architectural improvements planned in subsequent phases. The SOLID refactoring will make the codebase more maintainable and extensible, while the CAP compliance work will prepare MoonlightOS for future distributed deployments.

By following this roadmap, MoonlightOS will evolve from a single-node microkernel into a modular, reliable, and distributed-ready operating system with strong security guarantees maintained through formal verification.
