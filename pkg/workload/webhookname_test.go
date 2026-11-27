// Copyright 2026 vArmor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package workload

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func nameAdapter(resource, group string) FakeAdapter {
	return FakeAdapter{
		AdapterName: "fake-" + resource,
		AdapterGVK:  gvk(group, "v1", "Fake"),
		AdapterGVR:  gvr(group, "v1", resource),
	}
}

// truncatedSuffixPattern matches the '-' plus 16 lowercase hex chars that
// precede the retained .varmor.org suffix of every truncated entry name.
var truncatedSuffixPattern = regexp.MustCompile(`-[0-9a-f]{16}\.varmor\.org$`)

// dnsSubdomainOfLen builds a valid DNS-1123 subdomain of exactly n chars out
// of 'a' labels of at most 63, for tests needing precise raw-name lengths.
func dnsSubdomainOfLen(t *testing.T, n int) string {
	t.Helper()
	var b strings.Builder
	for b.Len() < n {
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		label := n - b.Len()
		if label > validation.DNS1123LabelMaxLength {
			label = validation.DNS1123LabelMaxLength
		}
		b.WriteString(strings.Repeat("a", label))
	}
	out := b.String()
	if len(out) != n {
		t.Fatalf("test setup: built subdomain of %d chars, want %d", len(out), n)
	}
	if errs := validation.IsDNS1123Subdomain(out); len(errs) != 0 {
		t.Fatalf("test setup: %q is not a DNS-1123 subdomain: %v", out, errs)
	}
	return out
}

// fullyQualifiedNameFieldPath mirrors the API server's validation site for
// webhooks[].name.
func fullyQualifiedNameFieldPath() *field.Path {
	return field.NewPath("webhooks").Index(0).Child("name")
}

// TestWebhookEntryName_ShortNameUnchanged pins the no-op fast path.
func TestWebhookEntryName_ShortNameUnchanged(t *testing.T) {
	a := nameAdapter("gameservers", "gaming.example.com")

	name, truncated := WebhookEntryName(a)
	if truncated {
		t.Fatalf("short name must not be truncated, got %q", name)
	}
	if want := "mutate-gameservers.gaming.example.com.varmor.org"; name != want {
		t.Fatalf("rendered %q, want %q", name, want)
	}
}

// TestWebhookEntryName_OverflowTruncatesAndStaysValid is the core fix: an
// over-long identity keeps its resource/group body and fixed framing, with a
// 16-hex-char SHA-256 hash inserted before .varmor.org, deterministically.
func TestWebhookEntryName_OverflowTruncatesAndStaysValid(t *testing.T) {
	// 63-char resource (DNS-label maximum) plus a 253-char group guarantees
	// the rendered name overflows 253.
	resource := strings.Repeat("a", 63)
	group := strings.Repeat("b.", 126) + "b" // 253 chars, valid DNS subdomain
	if len(group) != validation.DNS1123SubdomainMaxLength {
		t.Fatalf("test setup: group length %d, want 253", len(group))
	}
	a := nameAdapter(resource, group)

	if raw := rawWebhookEntryName(a); len(raw) <= validation.DNS1123SubdomainMaxLength {
		t.Fatalf("test setup: raw name must overflow, got %d chars", len(raw))
	}

	name, truncated := WebhookEntryName(a)
	if !truncated {
		t.Fatal("over-long name must report truncation")
	}
	if len(name) > validation.DNS1123SubdomainMaxLength {
		t.Fatalf("truncated name is %d chars, exceeding the 253 limit: %q", len(name), name)
	}
	if !strings.HasPrefix(name, webhookNamePrefix) {
		t.Fatalf("truncated name %q must retain the %q prefix", name, webhookNamePrefix)
	}
	if !strings.HasSuffix(name, webhookNameSuffix) {
		t.Fatalf("truncated name %q must retain the %q suffix", name, webhookNameSuffix)
	}
	// The full 63-char plural survives at the front of the body, so the
	// entry stays recognizable rather than collapsing to a bare hash.
	if wantPrefix := webhookNamePrefix + resource + "."; !strings.HasPrefix(name, wantPrefix) {
		t.Fatalf("truncated name %q must retain the full resource prefix %q", name, wantPrefix)
	}
	if errs := validation.IsDNS1123Subdomain(name); len(errs) != 0 {
		t.Fatalf("truncated name %q fails DNS-1123 subdomain validation: %v", name, errs)
	}
	if errs := validation.IsFullyQualifiedName(fullyQualifiedNameFieldPath(), name); len(errs) != 0 {
		t.Fatalf("truncated name %q fails IsFullyQualifiedName: %v", name, errs)
	}
	// The API server requires at least three dot-separated segments; assert
	// the shape explicitly so a regression below the FQDN minimum reads
	// clearly even though IsFullyQualifiedName already implies it.
	if got := len(strings.Split(name, ".")); got < 3 {
		t.Fatalf("truncated name %q must keep at least 3 dot-separated segments, got %d", name, got)
	}
	if !truncatedSuffixPattern.MatchString(name) {
		t.Fatalf("truncated name %q must embed '-' plus 16 lowercase hex chars before the fixed suffix", name)
	}

	if again, _ := WebhookEntryName(a); again != name {
		t.Fatalf("non-deterministic rendering: %q vs %q", name, again)
	}
}

// TestWebhookEntryName_OverflowRetainsBodyPrefix proves truncation keeps
// whole leading group labels rather than cutting one in half or collapsing
// the body to a bare hash: the first 63-char label of the group must appear
// intact in the rendered name. Resource-prefix retention and the generic
// length/DNS/FQDN battery belong to TestWebhookEntryName_OverflowTruncatesAndStaysValid.
func TestWebhookEntryName_OverflowRetainsBodyPrefix(t *testing.T) {
	resource := "widgets"
	group := dnsSubdomainOfLen(t, 228) // forces a 254-char raw name
	a := nameAdapter(resource, group)
	if raw := rawWebhookEntryName(a); len(raw) <= validation.DNS1123SubdomainMaxLength {
		t.Fatalf("test setup: raw name must overflow, got %d chars", len(raw))
	}

	name, truncated := WebhookEntryName(a)
	if !truncated {
		t.Fatal("over-long name must report truncation")
	}
	// The first group label is a 63-char run of 'a' and must survive whole.
	if !strings.Contains(name, "."+strings.Repeat("a", validation.DNS1123LabelMaxLength)+".") {
		t.Fatalf("truncated name %q must retain the whole leading group label", name)
	}
}

// TestWebhookEntryName_TruncationBoundary pins the exact 253-char threshold:
// raw names of 252/253 chars pass through unchanged while 254/255 truncate,
// guarding against an off-by-one in the limit comparison.
func TestWebhookEntryName_TruncationBoundary(t *testing.T) {
	// raw = "mutate-" (7) + "widgets" (7) + "." (1) + group + ".varmor.org" (11)
	const fixedOverhead = 26
	testCases := []struct {
		rawLen    int
		truncated bool
	}{
		{252, false},
		{253, false},
		{254, true},
		{255, true},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("rawLen=%d", tc.rawLen), func(t *testing.T) {
			group := dnsSubdomainOfLen(t, tc.rawLen-fixedOverhead)
			a := nameAdapter("widgets", group)
			raw := rawWebhookEntryName(a)
			if len(raw) != tc.rawLen {
				t.Fatalf("test setup: raw name is %d chars, want %d", len(raw), tc.rawLen)
			}

			name, truncated := WebhookEntryName(a)
			if truncated != tc.truncated {
				t.Fatalf("truncated = %v for raw length %d, want %v", truncated, tc.rawLen, tc.truncated)
			}
			if !tc.truncated {
				if name != raw || len(name) != tc.rawLen {
					t.Fatalf("raw length %d must render unchanged, got %q", tc.rawLen, name)
				}
				return
			}
			if len(name) > validation.DNS1123SubdomainMaxLength {
				t.Fatalf("truncated name exceeds 253 chars: %d", len(name))
			}
			if !strings.HasPrefix(name, webhookNamePrefix+"widgets.") {
				t.Fatalf("truncated name %q must retain the resource prefix", name)
			}
			if errs := validation.IsDNS1123Subdomain(name); len(errs) != 0 {
				t.Fatalf("truncated name fails DNS-1123 subdomain validation: %v", errs)
			}
			if errs := validation.IsFullyQualifiedName(fullyQualifiedNameFieldPath(), name); len(errs) != 0 {
				t.Fatalf("truncated name fails IsFullyQualifiedName: %v", errs)
			}
			if !truncatedSuffixPattern.MatchString(name) {
				t.Fatalf("truncated name %q must embed the hash before the fixed .varmor.org suffix", name)
			}
		})
	}
}

// TestWebhookEntryName_DistinctIdentitiesStayDistinct proves the SHA-256 hash
// of the full raw name disambiguates identities whose long common prefix
// would make a naive prefix truncation collapse them onto one entry.
func TestWebhookEntryName_DistinctIdentitiesStayDistinct(t *testing.T) {
	// The first 236 chars of both raw names are identical, so the
	// blue/green difference lives past any prefix cut and only the hash can
	// keep the entries apart.
	g1 := strings.Repeat("x", 230) + "blue"
	g2 := strings.Repeat("x", 230) + "green"
	a1 := nameAdapter("widgets", g1)
	a2 := nameAdapter("widgets", g2)

	raw1, raw2 := rawWebhookEntryName(a1), rawWebhookEntryName(a2)
	if raw1 == raw2 {
		t.Fatal("test setup: raw identities must differ")
	}
	if raw1[:236] != raw2[:236] {
		t.Fatal("test setup: raw names must share a long prefix so the hash is load-bearing")
	}

	name1, truncated1 := WebhookEntryName(a1)
	name2, truncated2 := WebhookEntryName(a2)
	if !truncated1 || !truncated2 {
		t.Fatal("both identities must overflow")
	}
	if name1 == name2 {
		t.Fatalf("distinct identities collapsed onto one entry name: %q", name1)
	}
	for _, n := range []string{name1, name2} {
		if errs := validation.IsFullyQualifiedName(fullyQualifiedNameFieldPath(), n); len(errs) != 0 {
			t.Fatalf("truncated name %q fails IsFullyQualifiedName: %v", n, errs)
		}
	}
}

// TestWebhookEntryName_AlwaysValidShape positions the group cut exactly on
// each separator TrimRight handles: one case cuts on a dot, the other on a
// hyphen. Without the trim the hash junction would start a label with '-'
// (invalid DNS-1123) in the dot case or produce a double-hyphen junction in
// the hyphen case, which DNS validation alone does not reject.
func TestWebhookEntryName_AlwaysValidShape(t *testing.T) {
	// 23 nine-char labels joined by dots: 22*10 + 9 = 229 chars. The
	// 10-char period ("aaaa-bbbb.") puts '-' at period offset 4 and '.' at
	// offset 9, so the cut character is set by the budget modulo 10.
	group := strings.Repeat("aaaa-bbbb.", 22) + "aaaa-bbbb"
	cases := []struct {
		name        string
		resource    string
		wantCutChar byte
	}{
		// budget = 217 - len(resource): 210 is a multiple of 10, so the
		// cut lands on the period ending the 21st label.
		{"cut lands on a dot", "widgets", '.'},
		// budget 205 = 20 full periods plus "aaaa-", so the cut lands on
		// the hyphen inside the next label.
		{"cut lands on a hyphen", "hyphenwidget", '-'},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := nameAdapter(tc.resource, group)
			if raw := rawWebhookEntryName(a); len(raw) <= validation.DNS1123SubdomainMaxLength {
				t.Fatalf("test setup: raw name must overflow, got %d chars", len(raw))
			}
			// Mirror the production budget from the shared constants to
			// prove the fixture really positions the cut on the intended
			// separator rather than an alphanumeric character.
			budget := validation.DNS1123SubdomainMaxLength -
				(len(webhookNamePrefix) + len(tc.resource) + 1 + len(webhookNameSuffix)) -
				1 - webhookNameHashHexLen
			if got := group[budget-1]; got != tc.wantCutChar {
				t.Fatalf("test setup: character at the cut is %q, want %q", got, tc.wantCutChar)
			}

			name, truncated := WebhookEntryName(a)
			if !truncated {
				t.Fatal("over-long name must report truncation")
			}
			if errs := validation.IsDNS1123Subdomain(name); len(errs) != 0 {
				t.Fatalf("truncated name %q fails DNS-1123 subdomain validation: %v", name, errs)
			}
			if errs := validation.IsFullyQualifiedName(fullyQualifiedNameFieldPath(), name); len(errs) != 0 {
				t.Fatalf("truncated name %q fails IsFullyQualifiedName: %v", name, errs)
			}
			if !truncatedSuffixPattern.MatchString(name) {
				t.Fatalf("truncated name %q must embed the hash before the fixed suffix", name)
			}
			// The separator at the cut must be stripped: the character
			// immediately before the "-<hash>.varmor.org" tail has to be
			// alphanumeric, never a dot or hyphen.
			junction := len(name) - len(webhookNameSuffix) - webhookNameHashHexLen - 1
			if c := name[junction-1]; c == '.' || c == '-' {
				t.Fatalf("truncated name %q keeps separator %q next to the hash junction", name, c)
			}
		})
	}
}
