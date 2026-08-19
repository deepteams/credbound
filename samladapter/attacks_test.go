package samladapter

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

// The suite already refuses a tampered response, a wrong audience, an expired
// assertion and a duplicated one. These are the SAML attacks that survive
// those checks in implementations that get them wrong: a response with no
// signature at all, a signature wrapped around a forged assertion, and the
// comment-truncation trick that splits a signed identifier without breaking
// the signature. Each must be refused, and none may echo the response XML
// back to the caller.

func decodeResponse(t *testing.T, encoded string) string {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return string(decoded)
}

func encodeResponse(document string) []byte {
	return []byte(base64.StdEncoding.EncodeToString([]byte(document)))
}

func assertRejected(t *testing.T, err error, attack string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s was accepted", attack)
	}
	// A rejection must not hand the attacker's document back in the error,
	// which would turn a log line into an echo of the forged assertion.
	if strings.Contains(err.Error(), "<saml") || strings.Contains(err.Error(), "<samlp") {
		t.Fatalf("%s rejection leaks response XML: %v", attack, err)
	}
}

// TestFinishRejectsUnsignedAssertion strips the signature the IdP produced.
// An implementation that only checks a signature when one is present accepts
// any assertion an attacker writes.
func TestFinishRejectsUnsignedAssertion(t *testing.T) {
	idp := newTestIdP(t)
	provider := newTestProvider(t, idp, nil)
	challenge, _ := begin(t, provider, false)
	document := decodeResponse(t, idp.respond(challenge.RedirectURL, defaultSession(), nil))

	// A response can carry a signature on the response element and another
	// on the assertion; the attack strips every one of them.
	unsigned, stripped := document, 0
	for {
		start := strings.Index(unsigned, "<ds:Signature")
		if start < 0 {
			break
		}
		end := strings.Index(unsigned[start:], "</ds:Signature>")
		if end < 0 {
			t.Fatal("unterminated ds:Signature element")
		}
		unsigned = unsigned[:start] + unsigned[start+end+len("</ds:Signature>"):]
		stripped++
	}
	if stripped == 0 {
		t.Fatalf("the signed response carries no ds:Signature element: %s", document[:min(len(document), 200)])
	}

	_, err := provider.Finish(context.Background(), challenge.Session, encodeResponse(unsigned))
	assertRejected(t, err, "an unsigned assertion")
}

// TestFinishRejectsSignatureWrapping performs the classic XML signature
// wrapping: the genuine signed assertion is moved inside an element the
// validator does not read, and a forged assertion carrying the attacker's
// NameID takes its place. A validator that hunts for "a valid signature
// somewhere in the document" accepts it; one that verifies the signature over
// the assertion it actually consumes does not.
func TestFinishRejectsSignatureWrapping(t *testing.T) {
	idp := newTestIdP(t)
	provider := newTestProvider(t, idp, nil)
	challenge, _ := begin(t, provider, false)
	document := decodeResponse(t, idp.respond(challenge.RedirectURL, defaultSession(), nil))

	start := strings.Index(document, "<saml:Assertion")
	end := strings.Index(document, "</saml:Assertion>")
	if start < 0 || end < 0 {
		t.Fatalf("no assertion found in %s", document[:min(len(document), 200)])
	}
	signed := document[start : end+len("</saml:Assertion>")]
	forged := strings.Replace(signed, "user-123", "user-999", 1)
	if forged == signed {
		t.Fatal("the forged assertion must differ from the signed one")
	}
	// The forged assertion carries the genuine one inside saml:Advice, which
	// is exactly where a naive "find any valid signature" check trips.
	wrapped := strings.Replace(forged, "</saml:Assertion>", "<saml:Advice>"+signed+"</saml:Advice></saml:Assertion>", 1)
	attack := document[:start] + wrapped + document[end+len("</saml:Assertion>"):]

	claims, err := provider.Finish(context.Background(), challenge.Session, encodeResponse(attack))
	if err == nil && claims.Subject == "user-999" {
		t.Fatal("signature wrapping produced the attacker's subject")
	}
	assertRejected(t, err, "a wrapped signature")
}

// TestFinishRejectsCommentTruncatedNameID inserts an XML comment inside the
// signed NameID. Canonicalization drops comments, so the signature can still
// verify while a parser that reads only the first text node sees a truncated
// identity — the flaw behind the 2018 round of SAML authentication bypasses.
// Either the response is refused, or the subject must be the whole text; what
// must never happen is the adapter reporting the truncated prefix.
func TestFinishRejectsCommentTruncatedNameID(t *testing.T) {
	idp := newTestIdP(t)
	provider := newTestProvider(t, idp, nil)
	challenge, _ := begin(t, provider, false)
	document := decodeResponse(t, idp.respond(challenge.RedirectURL, defaultSession(), nil))

	attack := strings.Replace(document, "user-123", "user-1<!---->23", 1)
	if attack == document {
		t.Fatal("the response does not carry the expected NameID")
	}

	claims, err := provider.Finish(context.Background(), challenge.Session, encodeResponse(attack))
	if err != nil {
		assertRejected(t, err, "a comment-truncated NameID")
		return
	}
	if claims.Subject != "user-123" {
		t.Fatalf("comment truncation changed the subject to %q", claims.Subject)
	}
}
