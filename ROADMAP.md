# Background

The original ic-py development team has ceased maintenance of the project. Having maintained a close relationship with the former team—we were jointly supported by the same incubator, now disbanded—I have secured consent from the core developers and the repository owner to continue development. Special thanks to @marc0olo and @eduard-galindo for their ongoing support.

Future maintenance of ic-py will primarily be conducted in [my repository](https://github.com/eliezhao/ic-py/tree/fix/issues). Updates will be submitted to the main repository via pull requests and subsequently released on PyPI.

# Current Issues and Approach

Based on feedback gathered from GitHub issues and forum discussions, I have identified and structured existing issues into clear milestones prioritized by urgency and complexity. My immediate focus is addressing known security vulnerabilities and simpler tasks with fewer dependencies or blockers.

## Related Discussions:

* [Unmaintained IC agents containing vulnerabilities](https://forum.dfinity.org/t/unmaintained-ic-agents-containing-vulnerabilities/41589)
* [Can DFINITY maintain ic-py?](https://forum.dfinity.org/t/can-dfinity-maintain-ic-py/36955)

---

# Roadmap & Milestones

## Guiding Principles

* Resolve all known security vulnerabilities.
* Modernize and fully support the Candid type system.
* Maintain alignment with agent-rs's feature set and release schedule.

---

## Milestone 1 ✅ *Completed*

- **Endpoint upgrade**
    - **Issue:** ic-py was pointing at legacy endpoints and needed to switch to v3/v4
    - **References:**
        - [Reducing end-to-end latencies on the Internet Computer](https://forum.dfinity.org/t/reducing-end-to-end-latencies-on-the-internet-computer/34383)
        - [Boundary Node Roadmap (latest v3/v4 endpoints)](https://forum.dfinity.org/t/boundary-node-roadmap/15562/104?u=c-b-elite)
    - **Solution:** 
        1. Updated ic-py's default endpoints to the latest BN v3/v4 addresses:
           - Query: `/api/v3/canister/<canister_id>/query`
           - Call: `/api/v4/canister/<canister_id>/call`
           - Read State: `/api/v3/canister/<canister_id>/read_state`
           - Read Subnet State: `/api/v3/subnet/<subnet_id>/read_state`
        2. Established maintenance tracking for future roadmap changes

- **Timeouts & error classification**
    - **Issues:** Missing timeouts on agent calls; lack of fine-grained error categories for canister responses (e.g. exhausted cycles, missing WASM)
    - **References:** [#117](https://github.com/rocklabs-io/ic-py/issues/117) • [#115](https://github.com/rocklabs-io/ic-py/issues/115)
    - **Solution:**
        1. Implemented configurable timeouts on all agent calls
        2. Introduced structured error types for common canister-level failures
        3. Created comprehensive error hierarchy with 11 error classes (`ICError`, `TransportError`, `SecurityError`, `ReplicaReject`, etc.)

---

## Milestone 2 ✅ *Completed*

- **IC certificate verification**
    - **Issue:** `request_status_raw` and `request_status_raw_async` did not verify certificates, allowing a malicious node to tamper with update responses
    - **References:**
        - DFINITY forum: [Unmaintained IC agents containing vulnerabilities](https://forum.dfinity.org/t/unmaintained-ic-agents-containing-vulnerabilities/41589?u=marc0olo)
        - GitHub issue [#109](https://github.com/rocklabs-io/ic-py/issues/109)
        - PR [#56](https://github.com/rocklabs-io/ic-py/pull/56/files) • issue [#76](https://github.com/rocklabs-io/ic-py/issues/76)
    - **Solution:**
        1. Mirrored agent-rs's certificate-checking logic ([agent-rs implementation](https://github.com/dfinity/agent-rs/blob/b53d770cfd07df07b1024cfd9cc25f7ff80d1b76/ic-agent/src/agent/mod.rs#L903))
        2. Resolved Python–BLS compatibility by bridging Rust BLS crate via FFI
        3. ✅ Certificate verification enabled by default in `update_raw` and `update_raw_async` methods
        4. ✅ Certificate verification implemented in `poll` and `poll_async` methods
        5. ✅ Certificate verification enabled by default in `request_status_raw` and `request_status_raw_async` methods
        6. ✅ Support for V4 API sharded `canister_ranges` structure in certificate verification
        7. ✅ Enhanced certificate delegation path handling and node key caching

---

## Milestone 3 ✅ *Completed*

- **Candid type-system enhancements**
    - **Issue:** Missing support for the latest Candid features (e.g. composite queries, new primitives)
    - **References:**
        - [#111](https://github.com/rocklabs-io/ic-py/issues/111) • [PR #112](https://github.com/rocklabs-io/ic-py/pull/112/files) • [#63](https://github.com/rocklabs-io/ic-py/issues/63)
        - [Latest Candid spec](https://github.com/dfinity/candid)
    - **Solution:**
        1. ✅ Migrated from Python ANTLR4 implementation to Rust-based `candid-parser` crate for significant performance improvements (multiple times faster parsing speed)
        2. ✅ Implemented comprehensive DIDLoader interface with support for recursive type definitions and service interface parsing
        3. ✅ Added comprehensive test suite (`test_candid_comprehensive.py`, `test_did_loader_comprehensive.py`, `test_parser.py`)
        4. ✅ Full support for all Candid primitives, composite types (Record, Variant, Vec, Opt), and recursive types
        5. ✅ Fixed VarT (type reference) handling in Candid DID parser, supporting `service : () -> TypeName` pattern and nested type references

---

## Milestone 4 ✅ *Completed*

- **Expanded API surface**
    - ✅ High-level wrappers for ICP Ledger (`ledger.py`)
    - ✅ Complete NNS Governance interface implementation (`governance.py` - 1510 lines)
    - ✅ Cycles Wallet operations (`cycles_wallet.py`)
    - ✅ Canister Management interface (`management.py`)
    - ✅ Comprehensive example code library (ledger, governance, cycles_wallet, management, simple_counter examples)
    - ⏳ High-level wrappers for ICRC-compliant ledgers (ckBTC, ckETH, ckUSDc, etc.)
    - ⏳ Out-of-the-box helpers for interacting with Bitcoin, Ethereum, and other canisters

- **Code optimization**
    - ✅ Simplified `canister.py` from 1322 lines to ~112 lines (90%+ reduction)
    - ✅ Improved code structure and maintainability
    - ✅ Better error handling and dynamic method binding support

- **Additional improvements**
    - ✅ HTTP/2 support enabled in all async methods (`AsyncClient`) for improved performance
    - ✅ Structured error handling hierarchy with 11 error classes exported from `icp_core`
    - ✅ Enhanced certificate verification with improved error messages and subnet-level read_state operations

---

## Milestone 5 (Next Release)

- **Automatically fetch the .did file from the canister**
    - **Issue:** Currently, users must manually provide DID files when creating Canister instances
    - **Solution:** Implement automatic DID file retrieval from canister's `__get_candid_interface_tmp_hack` method or similar mechanisms

- **High-level async API methods**
    - **Issue:** While low-level async methods (`update_raw_async`, `query_raw_async`) exist, high-level convenience methods (`update_async`, `query_async`) are missing, making async programming less ergonomic
    - **Solution:** 
        - Add `Agent.update_async()` and `Agent.query_async()` methods to provide async counterparts to the synchronous `update()` and `query()` methods
        - Ensure these methods support the same auto-encoding behavior and certificate verification options as their synchronous counterparts
        - Enable seamless async/await patterns for canister interactions

- **Canister async method support**
    - **Issue:** Canister wrapper class currently generates synchronous methods only, requiring users to manually use `update_raw_async` or `query_raw_async` for async operations
    - **Solution:** 
        - Automatically generate async method variants for all canister methods (e.g., `canister.method_name_async()`)
        - Ensure async methods maintain the same type safety and convenience features as synchronous methods
        - Provide consistent async/await support across the entire API surface

- **Replica-signed queries**
    - **Issue:** Query calls currently do not support replica-signed responses for enhanced security
    - **Status:** Query signature verification is temporarily disabled in v2.2.0 due to certificate delegation issues
    - **Solution:** Enable replica signature verification once certificate delegation issues are resolved

---

### Other long-standing bugs

- **Dynamic HTTP provider & routing**
    - **Issue:** Current implementation uses fixed endpoints without adaptive routing
    - **Solution:** 
        - Implement latency-based, adaptive routing between boundary nodes
        - Support more flexible selection of endpoints at runtime

- **High-level wrappers for ICRC-compliant ledgers (ckBTC, ckETH, ckUSDc, etc.)**

- **Out-of-the-box helpers for interacting with Bitcoin, Ethereum, and other canisters**

- **Precision of returned data**
    - Issue [#107](https://github.com/rocklabs-io/ic-py/issues/107) – floating-point vs. integer handling

---

Feel free to suggest improvements or features here. Your feedback will help refine the roadmap and guide ongoing development.

Let's collaborate to enhance ic-py and empower more developers to build reliable ICP applications!
