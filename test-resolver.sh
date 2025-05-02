#!/usr/bin/env bash

DNSSEC_RESOLVER=$1

echo "------Testing proper implementation of the DNSSEC validation algorithm RFC 4035 Section 5"
EXPIRED_RESULT="$(dig @$DNSSEC_RESOLVER expired.caatestsuite-dnssec.com IN CAA \
)"
if echo $EXPIRED_RESULT | grep -q "status: SERVFAIL" ; then
    echo "expired.caatestsuite-dnssec.com PASSED"
else
    echo "expired.caatestsuite-dnssec.com FAILED"
    exit 1
fi


MISSING_RESULT="$(dig @$DNSSEC_RESOLVER missing.caatestsuite-dnssec.com IN CAA \
)"
if echo $MISSING_RESULT | grep -q "status: SERVFAIL" ; then
    echo "missing.caatestsuite-dnssec.com PASSED"
else
    echo "missing.caatestsuite-dnssec.com FAILED"
    exit 1
fi

BLACKHOLE_RESULT="$(dig @$DNSSEC_RESOLVER blackhole.caatestsuite-dnssec.com IN CAA \
)"
if echo $BLACKHOLE_RESULT | grep -q "status: SERVFAIL" ; then
    echo "blackhole.caatestsuite-dnssec.com PASSED"
else
    echo "blackhole.caatestsuite-dnssec.com FAILED"
    exit 1
fi

SERVFAIL_RESULT="$(dig @$DNSSEC_RESOLVER servfail.caatestsuite-dnssec.com IN CAA \
)"
if echo $SERVFAIL_RESULT | grep -q "status: SERVFAIL" ; then
    echo "servfail.caatestsuite-dnssec.com PASSED"
else
    echo "servfail.caatestsuite-dnssec.com FAILED"
    exit 1
fi


REFUSED_RESULT="$(dig @$DNSSEC_RESOLVER refused.caatestsuite-dnssec.com IN CAA \
)"
if echo $REFUSED_RESULT | grep -q "status: SERVFAIL" ; then
    echo "refused.caatestsuite-dnssec.com PASSED"
else
    echo "refused.caatestsuite-dnssec.com FAILED"
    exit 1
fi

echo "------Test support for digest type 2 (SHA-2) RFC 4509, RRSIG type 8 (SHA-2 over RSA) RFC 5702, and optional RRSIG type 13."
CLOUDFLARE_CAA_RESULT="$(dig @$DNSSEC_RESOLVER cloudflare.com IN CAA \
)"
if echo $CLOUDFLARE_CAA_RESULT | grep -q "status: NOERROR" && echo $CLOUDFLARE_CAA_RESULT | grep -q "flags:[a-z ]*ad" ; then
    echo "cloudflare.com test PASSED"
else
    echo "cloudflare.com test FAILED"
    exit 1
fi

echo "------Test support for NSEC RFC 4035 Section 5."
CLOUDFLARE_NXSUBDOMAIN_RESULT="$(dig @$DNSSEC_RESOLVER a-subdomain-that-does-not-exist.cloudflare.com IN A \
)"
if echo $CLOUDFLARE_NXSUBDOMAIN_RESULT | grep -q "status: NOERROR" && echo $CLOUDFLARE_NXSUBDOMAIN_RESULT | grep -q "ANSWER: 0" && echo $CLOUDFLARE_NXSUBDOMAIN_RESULT | grep -q "flags:[a-z ]*ad" ; then
    echo "a-subdomain-that-does-not-exist.cloudflare.com test PASSED"
else
    echo "a-subdomain-that-does-not-exist.cloudflare.com test FAILED"
    exit 1
fi

echo "------Test support for NSEC3 RFC 5155."
CN_RESULT="$(dig @$DNSSEC_RESOLVER cn IN A \
)"
if echo $CN_RESULT | grep -q "status: NOERROR" && echo $CN_RESULT | grep -q "ANSWER: 0" && echo $CN_RESULT | grep -q "flags:[a-z ]*ad" ; then
    echo "cn test PASSED"
else
    echo "cn test FAILED"
    exit 1
fi

echo "ALL TESTS PASSED"