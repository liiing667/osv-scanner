package sourceanalysis

import (
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/v2/internal/sourceanalysis/govulncheck"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/google/osv-scanner/v2/pkg/models"
)

func Test_matchAnalysisWithPackageVulns(t *testing.T) {
	t.Parallel()

	pkgs := testutility.LoadJSONFixture[[]models.PackageVulns](t, "testdata/json/input.json")
	gvcResByVulnID := testutility.LoadJSONFixture[map[string][]*govulncheck.Finding](t, "testdata/json/govulncheckinput.json")
	vulnsByID := testutility.LoadVulnMapFixture(t, "testdata/json/vulnbyid.json")

	matchAnalysisWithPackageVulns(pkgs, gvcResByVulnID, vulnsByID)

	testutility.NewSnapshot().MatchJSON(t, pkgs)
}

func Test_matchEmptyAnalysisWithPackageVulns(t *testing.T) {
	t.Parallel()

	pkgs := testutility.LoadJSONFixture[[]models.PackageVulns](t, "testdata/json/input-no-call-data.json")
	// When there is no ecosystem specific data, govulncheck will return no results
	gvcResByVulnID := map[string][]*govulncheck.Finding{}
	vulnsByID := testutility.LoadVulnMapFixture(t, "testdata/json/vulnbyid-no-call-data.json")

	matchAnalysisWithPackageVulns(pkgs, gvcResByVulnID, vulnsByID)

	testutility.NewSnapshot().MatchJSON(t, pkgs)
}

func Test_matchAnalysisWithPackageVulns_findingOrderIndependent(t *testing.T) {
	t.Parallel()

	basePkgs := testutility.LoadJSONFixture[[]models.PackageVulns](t, "testdata/json/input.json")
	baseFindings := testutility.LoadJSONFixture[map[string][]*govulncheck.Finding](t, "testdata/json/govulncheckinput.json")
	vulnsByID := testutility.LoadVulnMapFixture(t, "testdata/json/vulnbyid.json")

	// GO-2023-1558 has both symbol-less findings (imported but no reachable
	// symbol) and a finding with a full call trace. Reversing the order must
	// not change the aggregated reachability result.
	reversedFindings := map[string][]*govulncheck.Finding{}
	for id, findings := range baseFindings {
		reversedFindings[id] = append([]*govulncheck.Finding(nil), findings...)
		slices.Reverse(reversedFindings[id])
	}

	run := func(findings map[string][]*govulncheck.Finding) map[string]map[string]models.AnalysisInfo {
		pkgs := append([]models.PackageVulns(nil), basePkgs...)
		matchAnalysisWithPackageVulns(pkgs, findings, vulnsByID)

		got := map[string]map[string]models.AnalysisInfo{}
		for _, pv := range pkgs {
			for _, group := range pv.Groups {
				got[pv.Package.Name] = group.ExperimentalAnalysis
			}
		}

		return got
	}

	original := run(baseFindings)
	reversed := run(reversedFindings)

	if diff := cmp.Diff(original, reversed); diff != "" {
		t.Fatalf("analysis differs based on finding ordering (-original +reversed):\n%s", diff)
	}

	analysis := reversed["github.com/ipfs/go-bitfield"]["GO-2023-1558"]
	if analysis.Called == nil {
		t.Fatal("expected GO-2023-1558 to be marked as called, got unknown (nil Called)")
	}
	if !*analysis.Called {
		t.Fatal("expected GO-2023-1558 to be marked as called, got called=false")
	}

	// GO-2021-0053 only has symbol-less findings: reachability is unknown, so
	// Called must stay nil instead of being reported as a definite false.
	unknown := reversed["github.com/gogo/protobuf"]["GO-2021-0053"]
	if unknown.Called != nil {
		t.Fatalf("expected unknown reachability (nil Called), got called=%v", *unknown.Called)
	}
}
