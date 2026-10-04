# SOLID Principles Analysis & Refactoring Plan

## Current State Analysis

### Single Responsibility Principle (SRP)

**Violations:**
1. **`kernel/kboot.c` (2500+ lines)** - Monolithic file handling:
   - Boot sequence
   - IPC syscalls (SEND/RECV/NOTIFY/WAIT)
   - Scheduling and thread management
   - Capability management (mint/grant/map/unmap/revoke)
   - ELF loading and validation
   - Page table management
   - IRQ handling
   - Virtio device initialization
   - Qube management

2. **Service modules** - Mix concerns:
   - IPC protocol handling
   - Business logic (e.g., console rendering, TTY line discipline)
   - Hardware interaction

**Good Examples:**
- `kernel/ipc.h` - Pure IPC queue logic
- `kernel/caps.h` - Capability operations
- `kernel/qube.h` - Qube label/policy logic
- `kernel/elf.h` - ELF validation
- `kernel/frames.h` - Frame pool management

### Open/Closed Principle (OCP)

**Violations:**
1. **Hard-coded thread/endpoint mapping:**
   ```c
   #define EP_OF_TID(t) (t) /* EP i owned by tid i */
   ```
   - Adding services requires kernel rebuild
   - Cannot reconfigure endpoints at runtime

2. **Fixed service catalog:**
   ```c
   #define T_MEM 2
   #define T_QREXEC 3
   #define T_ADMIN 4
   ...
   ```
   - Requires code changes to add services
   - No dynamic service registration

3. **Hard-coded message types:**
   ```c
   #define MSG_GUI_KEY_EVENT 0x1000
   #define MSG_CONSOLE_PUTC 0x2000
   ```
   - Adding message types requires protocol header changes
   - No extensibility mechanism

**Good Examples:**
- Capability system allows dynamic permission grants
- INVOKE operations table is extensible

### Liskov Substitution Principle (LSP)

**Status:** Not directly applicable (C language, no class hierarchy)

**Considerations:**
- Service endpoints are not polymorphic
- Could benefit from service interface abstractions
- Message handlers should be substitutable

### Interface Segregation Principle (ISP)

**Violations:**
1. **Monolithic IPC protocol header:**
   - `ipc_protocol.h` contains ALL message types
   - Services must include entire header even if they use 2-3 message types
   - Coupling between unrelated services

2. **Kernel syscall interface:**
   - All services see all syscalls even if they only use SEND/RECV
   - No fine-grained capability groups

**Good Examples:**
- Minimal kernel syscall set (8 syscalls)
- Capability system provides least-privilege access

### Dependency Inversion Principle (DIP)

**Violations:**
1. **Direct syscall dependencies:**
   ```c
   static long usend(unsigned long ep, const uint64_t *p, unsigned long n)
   {
       return u_ecall3(V2_SEND, (long)ep, (long)p, (long)n);
   }
   ```
   - High-level services depend directly on low-level syscalls
   - No abstraction layer

2. **Hard-coded thread ID dependencies:**
   ```c
   if (usend(10, fill, 4) != 0)  // Hard-coded GUI thread ID
       upark();
   ```
   - Tight coupling to specific thread numbers
   - Cannot relocate services

3. **Service discovery by index:**
   ```c
   initrd_lookup(3, &elf_data, &elf_size)  // Magic number
   ```
   - Services found by index, not name
   - Fragile to initrd ordering changes

**Good Examples:**
- Capability system provides some indirection
- Abstract endpoints (EPs) decouple from physical threads

---

## Refactoring Plan

### Phase 1: Kernel Modularization (SRP + OCP)

**Goal:** Split `kboot.c` into focused modules

**Actions:**
1. Create `kernel/syscall.c` - Syscall dispatch table and handlers
   - Move all syscall case statements from kboot.c
   - Implement syscall registration mechanism
   - Add syscall versioning

2. Create `kernel/sched.c` - Scheduling logic
   - Move `pick_next()`, `enter_thread()`, thread state management
   - Implement scheduler policy as pluggable module
   - Add scheduler statistics

3. Create `kernel/device.c` - Device management
   - Move virtio device scanning and initialization
   - Implement device registry
   - Add device lifecycle management

4. Create `kernel/elf_loader.c` - ELF loading
   - Move ELF loading logic from kboot.c
   - Add initrd management
   - Implement ELF verification pipeline

5. Refactor `kboot.c` to orchestration-only
   - Keep boot sequence coordination
   - Call module initialization functions
   - Reduce to ~500 lines

**Benefits:**
- Each module has single responsibility
- Easier to test individual components
- Enables concurrent development
- Reduces cognitive load per file

### Phase 2: Dynamic Service Registration (OCP + DIP)

**Goal:** Allow runtime service discovery and registration

**Actions:**
1. Implement service registry:
   ```c
   typedef struct {
       char name[32];
       uint32_t version;
       uint32_t capabilities;
       void (*init_fn)(void);
       void (*cleanup_fn)(void);
   } service_descriptor_t;
   ```

2. Add service registration syscall:
   ```c
   V2_INV_REGISTER_SERVICE(name, version, capabilities, init_fn, cleanup_fn)
   ```

3. Implement service discovery:
   - Service lookup by name instead of index
   - Capability-based service binding
   - Hot-reload support (future)

4. Remove hard-coded thread/endpoint mappings:
   - Implement dynamic endpoint allocation
   - Add endpoint-to-service mapping table
   - Support service migration

**Benefits:**
- Services can be added without kernel rebuild
- Flexible service deployment
- Better for testing and development

### Phase 3: IPC Protocol Modularization (ISP + OCP)

**Goal:** Split monolithic IPC protocol into service-specific modules

**Actions:**
1. Create service-specific protocol headers:
   - `services/gui_protocol.h` - GUI messages only
   - `services/console_protocol.h` - Console messages only
   - `services/tty_protocol.h` - TTY messages only
   - `services/app_protocol.h` - Application messages only

2. Implement message type registry:
   ```c
   typedef struct {
       uint32_t msg_type;
       const char *msg_name;
       size_t msg_size;
       void (*handler_fn)(void *msg);
   } msg_descriptor_t;
   ```

3. Add message registration API:
   ```c
   ipc_register_message_type(&descriptor);
   ```

4. Refactor IPC helpers to use descriptors:
   - Type-safe message construction
   - Runtime message validation
   - Automatic message marshaling

**Benefits:**
- Services only include protocol they need
- Easier to add new message types
- Better compile-time isolation
- Enables protocol versioning

### Phase 4: Service Interface Abstraction (DIP + LSP)

**Goal:** Define service interfaces for polymorphism

**Actions:**
1. Define service interface:
   ```c
   typedef struct {
       int (*send)(const void *msg, size_t len);
       int (*recv)(void *msg, size_t cap);
       int (*query)(uint32_t what, void *result);
       int (*control)(uint32_t cmd, void *arg);
   } service_interface_t;
   ```

2. Implement service proxy:
   - Generic service wrapper
   - Handles IPC marshaling
   - Provides error handling

3. Create service factories:
   - Instantiate services by interface
   - Support mock implementations for testing
   - Enable service composition

**Benefits:**
- Services depend on interfaces, not implementations
- Easier to mock for testing
- Enables service substitution
- Better for development and testing

### Phase 5: Capability System Enhancement (DIP)

**Goal:** Improve capability-based dependency management

**Actions:**
1. Implement capability namespaces:
   - Separate capability spaces per service
   - Cross-service capability grants
   - Capability inheritance

2. Add capability introspection:
   - Query capability permissions
   - Validate capability chains
   - Audit capability usage

3. Implement capability brokers:
   - Service-specific capability management
   - Dynamic capability allocation
   - Capability revocation policies

**Benefits:**
- Better security isolation
- Flexible permission management
- Improved auditability

---

## Implementation Timeline

### Sprint 1 (Week 1-2): Kernel Modularization
- Split kboot.c into syscall.c, sched.c, device.c, elf_loader.c
- Update build system
- Run verification tests

### Sprint 2 (Week 3-4): Dynamic Service Registration
- Implement service registry
- Add registration syscall
- Refactor existing services to use registry
- Test service hot-loading

### Sprint 3 (Week 5-6): IPC Protocol Modularization
- Split ipc_protocol.h into service-specific headers
- Implement message type registry
- Refactor IPC helpers
- Update all services

### Sprint 4 (Week 7-8): Service Interface Abstraction
- Define service interfaces
- Implement service proxy
- Create service factories
- Refactor services to use interfaces

### Sprint 5 (Week 9-10): Capability Enhancement
- Implement capability namespaces
- Add capability introspection
- Implement capability brokers
- Update security model

---

## Success Metrics

### Code Quality
- Reduce kboot.c from 2500+ to <500 lines
- Each module <500 lines
- Cyclomatic complexity <10 per function
- Test coverage >80%

### Maintainability
- Service addition time: 2 days → 2 hours
- Build time impact: <10%
- Verification time: <5 minutes
- No regression in Isabelle proofs

### Performance
- No performance degradation
- Syscall overhead: <5% increase
- Memory overhead: <5% increase

---

## Risks and Mitigations

### Risk 1: Breaking Isabelle Proofs
**Mitigation:** Incremental proof updates, parallel verification branch

### Risk 2: Performance Regression
**Mitigation:** Benchmarking at each phase, performance gates

### Risk 3: Service Compatibility
**Mitigation:** Backward compatibility layer, gradual migration

### Risk 4: Increased Complexity
**Mitigation:** Clear documentation, architectural reviews

---

## Conclusion

The SOLID refactoring will significantly improve code maintainability, extensibility, and testability while preserving the microkernel's security guarantees. The phased approach minimizes risk and allows continuous verification.
