# dnssec-validator-test
Test a recursive DNS validator endpoint to see if it supports DNSSEC per a subset of the requirements in ballot SC085v2.

## Usage
`./test-resolver.sh <IP Address of DNS Resolver Being Tested>`

OR

`./test-resolver.sh`

If no resolver IP address is specified, the system default DNS resolver is used.

The script will echo `ALL TESTS PASSED` with a 0 exit code if successful.

A non-zero exit code or any test marked "FAILED" indicates a failure.

## A note on blackhole.caatestsuite-dnssec.com

blackhole.caatestsuite-dnssec.com involves a DNS server that does not answer a query. The resolver may stall on this query potentially causing the dig client to time out (potentially causing a failed test as the required "SERVFAIL" message is not observed). Many resolvers maintain negative caches so this can be alleviated by trying again. If the problem persists, try adjusting the dig command's timeout or the DNS resolver's timeout.
