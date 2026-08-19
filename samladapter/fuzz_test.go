package samladapter

import (
	"testing"
)

// FuzzParseMetadata pins the IdP metadata reader, the one place where an
// administrator pastes a third-party XML document into the library. Whatever
// the bytes are — truncated, entity-laden, namespace-confused — parsing must
// answer with an error or a descriptor, never panic and never both.
func FuzzParseMetadata(f *testing.F) {
	f.Add([]byte(``))
	f.Add([]byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"></EntityDescriptor>`))
	f.Add([]byte(`<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><EntityDescriptor entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"></IDPSSODescriptor></EntityDescriptor></EntitiesDescriptor>`))
	f.Add([]byte(`<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><EntityDescriptor>&e;</EntityDescriptor>`))
	f.Add([]byte(`<EntityDescriptor><!--comment--></EntityDescriptor>`))
	f.Add([]byte("<EntityDescriptor entityID=\"a\"\x00/>"))

	f.Fuzz(func(t *testing.T, document []byte) {
		entity, err := parseMetadata(document)
		if err != nil {
			if entity != nil {
				t.Fatalf("rejected metadata returned a descriptor: %#v", entity)
			}
			return
		}
		if entity == nil {
			t.Fatal("metadata parsed to a nil descriptor without an error")
		}
		if entity.EntityID == "" {
			t.Fatalf("accepted metadata carries no entity identifier: %#v", entity)
		}
	})
}
