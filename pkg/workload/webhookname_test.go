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
)

func nameAdapter(resource, group string) FakeAdapter {
	return FakeAdapter{
		AdapterName: "fake-" + resource,
		AdapterGVK:  gvk(group, "v1", "Fake"),
		AdapterGVR:  gvr(group, "v1", resource),
	}
}

// truncatedSuffixPattern matches the '-' plus 16 lowercase hex chars ending
// every truncated entry name.
var truncatedSuffixPattern = regexp.MustCompile(`-[0-9a-f]{16}$`)

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
// over-long identity becomes a DNS-1123 subdomain ending in a 16-hex-char
// SHA-256 suffix, deterministically.
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
	if errs := validation.IsDNS1123Subdomain(name); len(errs) != 0 {
		t.Fatalf("truncated name %q fails DNS-1123 subdomain validation: %v", name, errs)
	}
	if !truncatedSuffixPattern.MatchString(name) {
		t.Fatalf("truncated name %q must end in '-' plus 16 lowercase hex chars", name)
	}

	if again, _ := WebhookEntryName(a); again != name {
		t.Fatalf("non-deterministic rendering: %q vs %q", name, again)
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
			if errs := validation.IsDNS1123Subdomain(name); len(errs) != 0 {
				t.Fatalf("truncated name fails DNS-1123 subdomain validation: %v", errs)
			}
			if !truncatedSuffixPattern.MatchString(name) {
				t.Fatalf("truncated name %q must end in the hash suffix", name)
			}
		})
	}
}

// TestWebhookEntryName_DistinctIdentitiesStayDistinct proves the hash suffix
// disambiguates identities whose differences fall beyond the truncation cut.
func TestWebhookEntryName_DistinctIdentitiesStayDistinct(t *testing.T) {
	// The first 236 chars of both raw names are identical, so the blue/green
	// difference is past the cut and bare truncation would merge them.
	g1 := strings.Repeat("x", 230) + "blue"
	g2 := strings.Repeat("x", 230) + "green"
	a1 := nameAdapter("widgets", g1)
	a2 := nameAdapter("widgets", g2)

	raw1, raw2 := rawWebhookEntryName(a1), rawWebhookEntryName(a2)
	if raw1 == raw2 {
		t.Fatal("test setup: raw identities must differ")
	}
	if raw1[:236] != raw2[:236] {
		t.Fatal("test setup: kept prefixes must be identical so the hash suffix is load-bearing")
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
		if errs := validation.IsDNS1123Subdomain(n); len(errs) != 0 {
			t.Fatalf("truncated name %q fails DNS-1123 validation: %v", n, errs)
		}
	}
}

// TestWebhookEntryName_AlwaysValidShape covers cuts landing on dots and
// hyphens, where trailing-separator stripping is load-bearing.
func TestWebhookEntryName_AlwaysValidShape(t *testing.T) {
	// IsDNS1123Subdomain already enforces the 253-char limit alongside the
	// character rules, so one validator assertion per input is sufficient.
	cases := []struct {
		resource, group string
	}{
		{strings.Repeat("ab-", 20) + "ab", strings.Repeat("b.", 126) + "b"},
		{"widgets", strings.Repeat("very-long-label.", 14) + "example.com"},
	}
	for _, tc := range cases {
		name, truncated := WebhookEntryName(nameAdapter(tc.resource, tc.group))
		if !truncated {
			t.Fatalf("test setup: identity must overflow (resource=%d group=%d)", len(tc.resource), len(tc.group))
		}
		if errs := validation.IsDNS1123Subdomain(name); len(errs) != 0 {
			t.Fatalf("truncated name %q invalid: %v", name, errs)
		}
	}
}
