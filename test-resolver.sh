#!/usr/bin/env bash

if [ -z "$1" ]; then
    echo "------Using default system resolver"
    DNSSEC_RESOLVER=""
else
    echo "------Using $1 resolver"
    DNSSEC_RESOLVER="@$1"
fi

echo "------Testing proper implementation of the DNSSEC validation algorithm RFC 4035 Section 5"
EXPIRED_RESULT="$(dig $DNSSEC_RESOLVER expired.caatestsuite-dnssec.com IN CAA \
)"
if echo $EXPIRED_RESULT | grep -q "status: SERVFAIL" ; then
    echo "expired.caatestsuite-dnssec.com PASSED"
else
    echo "expired.caatestsuite-dnssec.com FAILED"
    exit 1
fi


MISSING_RESULT="$(dig $DNSSEC_RESOLVER missing.caatestsuite-dnssec.com IN CAA \
)"
if echo $MISSING_RESULT | grep -q "status: SERVFAIL" ; then
    echo "missing.caatestsuite-dnssec.com PASSED"
else
    echo "missing.caatestsuite-dnssec.com FAILED"
    exit 1
fi

BLACKHOLE_RESULT="$(dig $DNSSEC_RESOLVER blackhole.caatestsuite-dnssec.com IN CAA \
)"
if echo $BLACKHOLE_RESULT | grep -q "status: SERVFAIL" ; then
    echo "blackhole.caatestsuite-dnssec.com PASSED"
else
    echo "blackhole.caatestsuite-dnssec.com FAILED"
    exit 1
fi

SERVFAIL_RESULT="$(dig $DNSSEC_RESOLVER servfail.caatestsuite-dnssec.com IN CAA \
)"
if echo $SERVFAIL_RESULT | grep -q "status: SERVFAIL" ; then
    echo "servfail.caatestsuite-dnssec.com PASSED"
else
    echo "servfail.caatestsuite-dnssec.com FAILED"
    exit 1
fi


REFUSED_RESULT="$(dig $DNSSEC_RESOLVER refused.caatestsuite-dnssec.com IN CAA \
)"
if echo $REFUSED_RESULT | grep -q "status: SERVFAIL" ; then
    echo "refused.caatestsuite-dnssec.com PASSED"
else
    echo "refused.caatestsuite-dnssec.com FAILED"
    exit 1
fi

echo "------Test support for digest type 2 (SHA-2) RFC 4509 and RRSIG type 8 (SHA-2 over RSA) RFC 5702."
ORG_DS_RESULT="$(dig $DNSSEC_RESOLVER org IN DS \
)"
if ! ( echo "$ORG_DS_RESULT" | grep -q "status: NOERROR" && \
   echo "$ORG_DS_RESULT" | grep -q "flags:[a-z ]*ad" && \
   # Expect exactly one DS RR to simplify verification.
   [ $(echo "$ORG_DS_RESULT" | grep -c $'IN\tDS\t[0-9]\+') -eq 1 ] )
then
    echo "org test FAILED"
    exit 1
fi
# Capturing the key tag of the only DS RR with SHA-256 (2) DigestType.
re=$'IN\tDS\t([0-9]+) [0-9]+ 2'
if ! [[ $ORG_DS_RESULT =~ $re ]]; then
    echo "org test FAILED"
    exit 1
fi
ORG_DS_KEY_TAG="${BASH_REMATCH[1]}"
# Confirm the previous DS RR is actually understood by our resolver by checking support for its DNSKEY.
ORG_DNSKEY_RESULT=$(dig $DNSSEC_RESOLVER org IN DNSKEY \
+dnssec
)
if ! ( echo "$ORG_DNSKEY_RESULT" | grep -q "status: NOERROR" && \
   echo "$ORG_DNSKEY_RESULT" | grep -q "flags:[a-z ]*ad" && \
   [ $(echo "$ORG_DNSKEY_RESULT" | grep -c $'IN\tRRSIG\tDNSKEY') -eq 1 ] )
then
    echo "org test FAILED"
    exit 1
fi
# Capturing the key tag of the only RRSIG RR with RSA/SHA-256 (8) Algorithm Number.
re=$'IN\tRRSIG\tDNSKEY 8 1 [0-9]+ [0-9]+ [0-9]+ ([0-9]+)'
if ! [[ $ORG_DNSKEY_RESULT =~ $re ]]; then
    echo "org test FAILED"
    exit 1
fi
ORG_DNSKEY_KEY_TAG="${BASH_REMATCH[1]}"
if [ "$ORG_DNSKEY_KEY_TAG" != "$ORG_DS_KEY_TAG" ]; then
    echo "org test FAILED"
    exit 1
else
    echo "org test PASSED"
fi

echo "------Test support for optional RRSIG type 13 RFC 6605."
CLOUDFLARE_CAA_RESULT="$(dig $DNSSEC_RESOLVER cloudflare.com IN CAA \
+dnssec
)"
if echo $CLOUDFLARE_CAA_RESULT | grep -q "status: NOERROR" && \
   echo $CLOUDFLARE_CAA_RESULT | grep -q "flags:[a-z ]*ad" && \
   # Ensure there is a single RRSIG to be sure of having verified the right thing.
   [ $(echo "$CLOUDFLARE_CAA_RESULT" | grep -c $'IN\tRRSIG\tCAA') -eq 1 ] && \
   # Expect ECDSA Curve P-256 with SHA-256 (13) Algorithm Number.
   echo "$CLOUDFLARE_CAA_RESULT" | grep -q $'IN\tRRSIG\tCAA 13';
then
    echo "cloudflare.com test PASSED"
else
    echo "cloudflare.com test FAILED"
    exit 1
fi

echo "------Test support for NSEC RFC 4035 Section 5.4."
CLOUDFLARE_NXSUBDOMAIN_RESULT="$(dig $DNSSEC_RESOLVER a-subdomain-that-does-not-exist.cloudflare.com IN A \
+dnssec
)"
if echo $CLOUDFLARE_NXSUBDOMAIN_RESULT | grep -q "status: NOERROR" && \
   echo $CLOUDFLARE_NXSUBDOMAIN_RESULT | grep -q "flags:[a-z ]*ad" && \
   echo $CLOUDFLARE_NXSUBDOMAIN_RESULT | grep -q "ANSWER: 0" && \
   # Expecting no NSEC3 to ensure the resolver verified the right thing.
   ! (echo $CLOUDFLARE_NXSUBDOMAIN_RESULT | grep -q "IN NSEC3 ") && \
   echo $CLOUDFLARE_NXSUBDOMAIN_RESULT | grep -q "IN NSEC "
then
    echo "a-subdomain-that-does-not-exist.cloudflare.com test PASSED"
else
    echo "a-subdomain-that-does-not-exist.cloudflare.com test FAILED"
    exit 1
fi

echo "------Test support for NSEC3 RFC 5155."
CN_RESULT="$(dig $DNSSEC_RESOLVER cn IN A \
+dnssec
)"
if echo $CN_RESULT | grep -q "status: NOERROR" && \
   echo $CN_RESULT | grep -q "flags:[a-z ]*ad" && \
   echo $CN_RESULT | grep -q "ANSWER: 0" && \
   ! (echo $CN_RESULT | grep -q "IN NSEC ") && \
   echo $CN_RESULT | grep -q "IN NSEC3 "
then
    echo "cn test PASSED"
else
    echo "cn test FAILED"
    exit 1
fi

echo "ALL TESTS PASSED"
