# reference-kbs

A reference implementation of the [KBS](https://github.com/confidential-containers/kbs/).

## Attestation Server

While the [KBS](https://github.com/confidential-containers/kbs/) doesn't define the location of the component that does the attestation of the TEE measurements, allowing it to be a separate component from KBS, in this implementation that functionality is provided locally.
