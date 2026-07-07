# credex-policy-hook-reference

An example external policy hook for [Cofide Credex](https://docs.cofide.dev/credex/overview/).

## Overview

The [hook](./hook) directory contains a simple Go-based webserver which can act as an external policy hook for Credex.

The [hook/server.go](./hook/server.go) file contains `hookResponse` and `hookRequest` type definitions that any Credex policy hook must satisfy, as well as an example SPIFFE mTLS setup for secure communication between Credex and the external hook.

For more information, see the [Cofide Credex External Hooks documentation](https://docs.cofide.dev/credex/usage/#external-hooks).
