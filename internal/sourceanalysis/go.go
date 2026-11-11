// Package sourceanalysis provides functionality for performing source analysis on code.
package sourceanalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/sourceanalysis/govulncheck"
	"github.com/google/osv-scanner/v2/internal/url"
	"github.com/google/osv-scanner/v2/internal/utility/pathfilter"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"golang.org/x/vuln/scan"
	"google.golang.org/protobuf/encoding/protojson"
)

func goAnalysis(pkgs []models.PackageVulns, source models.SourceInfo) {
	// TODO: This will be moved to enrichers which does have context.
	cmd := exec.CommandContext(context.TODO(), "go", "version")
	_, err := cmd.Output()
	if err != nil {
		cmdlogger.Infof("Skipping call analysis on Go code since Go is not installed.")
		return
	}

	// Set GOVERSION to the Go version in go.mod.
	var goVersion string
	for _, pkg := range pkgs {
		if pkg.Package.Name == "stdlib" {
			goVersion = pkg.Package.Version
			break
		}
	}

	vulns, vulnsByID := vulnsFromAllPkgs(pkgs)
	// Filter out advisories with no symbol information first
	// This is purely an optimisation step, further filtering is done in matchAnalysisWithPackageVulns function
	filteredVulns := []*osvschema.Vulnerability{}
	for _, vuln := range vulns {
		if vulnHasImportsField(vuln, nil) {
			filteredVulns = append(filteredVulns, vuln)
		}
	}

	res, err := runGovulncheck(filepath.Dir(source.Path), filteredVulns, goVersion)
	if err != nil {
		// TODO: Better method to identify the type of error and give advice specific to the error
		cmdlogger.Errorf(
			"Failed to run code analysis (govulncheck) on '%s' because %s\n"+
				"(the Go toolchain is required)", source.Path, err.Error(),
		)

		return
	}
	matchAnalysisWithPackageVulns(pkgs, res, vulnsByID)
}

func matchAnalysisWithPackageVulns(pkgs []models.PackageVulns, idToFindings map[string][]*govulncheck.Finding, vulnsByID map[string]*osvschema.Vulnerability) {
	// idToModuleToCalled aggregates the findings per OSV ID and module.
	// A nil value means none of the findings carry symbol information, so
	// reachability is unknown; a true value means at least one finding has a
	// call trace reaching a vulnerable symbol. Every finding for the same OSV
	// and module must be considered, otherwise a finding without symbol
	// information (e.g. an alias or version-only record) could overwrite a
	// finding that proves the vulnerable symbol is called.
	idToModuleToCalled := map[string]map[string]*bool{}
	for id, findings := range idToFindings {
		idToModuleToCalled[id] = map[string]*bool{}
		for _, f := range findings {
			modulePath := f.Trace[0].Module
			// Findings with an empty function mean the package is imported but
			// govulncheck could not tie the finding to a called symbol. Such a
			// finding must not downgrade an already proven call path.
			if f.Trace[0].Function == "" {
				if _, exists := idToModuleToCalled[f.OSV][modulePath]; !exists {
					idToModuleToCalled[f.OSV][modulePath] = nil
				}

				continue
			}

			called := true
			idToModuleToCalled[f.OSV][modulePath] = &called
		}
	}

	for _, pv := range pkgs {
		// Use index to keep reference to original element in slice
		for groupIdx := range pv.Groups {
			for _, vulnID := range pv.Groups[groupIdx].IDs {
				analysis := &pv.Groups[groupIdx].ExperimentalAnalysis
				if *analysis == nil {
					*analysis = make(map[string]models.AnalysisInfo)
				}

				moduleToCalled, ok := idToModuleToCalled[vulnID]
				if !ok { // If vulnerability not found, check if it contains any source information
					fillNotImportedAnalysisInfo(vulnsByID, vulnID, pv, analysis)
					continue
				}

				called, hasFindingsForModule := moduleToCalled[pv.Package.Name]
				if !hasFindingsForModule {
					// govulncheck produced no finding for this module, so
					// reachability is unknown rather than definitely uncalled.
					(*analysis)[vulnID] = models.AnalysisInfo{}

					continue
				}

				// When the advisory has no symbol information, a proven call is
				// still reported, while symbol-less findings stay unknown.
				(*analysis)[vulnID] = models.AnalysisInfo{
					Called: called,
				}
			}
		}
	}
}

func vulnHasImportsField(vuln *osvschema.Vulnerability, pkg *models.PackageInfo) bool {
	if vuln == nil {
		return false
	}
	for _, affected := range vuln.GetAffected() {
		if pkg != nil {
			// TODO: Compare versions to see if this is the correct affected element
			// ver, err := semantic.Parse(pv.Package.Version, semantic.SemverVersion)
			if affected.GetPackage().GetName() != pkg.Name {
				continue
			}
		}
		if affected.GetEcosystemSpecific() == nil {
			continue
		}
		_, hasImportsField := affected.GetEcosystemSpecific().GetFields()["imports"]
		if hasImportsField {
			return true
		}
	}

	return false
}

// fillNotImportedAnalysisInfo checks for any source information in advisories, and sets called to false
func fillNotImportedAnalysisInfo(vulnsByID map[string]*osvschema.Vulnerability, vulnID string, pv models.PackageVulns, analysis *map[string]models.AnalysisInfo) {
	if vulnHasImportsField(vulnsByID[vulnID], &pv.Package) {
		// If there is source information, then analysis has been performed, and
		// code does not import the vulnerable package, so definitely not called
		called := false
		(*analysis)[vulnID] = models.AnalysisInfo{
			Called: &called,
		}
	}
}

func runGovulncheck(moddir string, vulns []*osvschema.Vulnerability, goVersion string) (map[string][]*govulncheck.Finding, error) {
	// Create a temporary directory containing all the vulnerabilities that
	// are passed in to check against govulncheck.
	//
	// This enables OSV scanner to supply the OSV vulnerabilities to run
	// against govulncheck and manage the database separately from vuln.go.dev.
	dbdir, err := os.MkdirTemp("", "")
	if err != nil {
		return nil, err
	}
	defer func() {
		rerr := os.RemoveAll(dbdir)
		if err == nil {
			err = rerr
		}
	}()

	root, err := os.OpenRoot(dbdir)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	for _, vuln := range vulns {
		dat, err := protojson.Marshal(vuln)
		if err != nil {
			return nil, err
		}
		if err := root.WriteFile(pathfilter.FilterPath(vuln.GetId())+".json", dat, 0600); err != nil {
			return nil, err
		}
	}

	// this only errors if the file path is not absolute,
	// which paths from os.MkdirTemp should always be
	dbdirURL, _ := url.FromFilePath(dbdir)

	// Run govulncheck on the module at moddir and vulnerability database that
	// was just created.
	cmd := scan.Command(context.Background(), "-db", dbdirURL.String(), "-C", moddir, "-json", "./...")
	var b bytes.Buffer
	cmd.Stdout = &b
	cmd.Env = append(os.Environ(), "GOVERSION=go"+goVersion)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if err := cmd.Wait(); err != nil {
		return nil, err
	}

	// Group the output of govulncheck based on the OSV ID.
	h := &osvHandler{
		idToFindings: map[string][]*govulncheck.Finding{},
	}
	if err := handleJSON(bytes.NewReader(b.Bytes()), h); err != nil {
		return nil, err
	}

	return h.idToFindings, nil
}

type osvHandler struct {
	idToFindings map[string][]*govulncheck.Finding
}

func (h *osvHandler) Finding(f *govulncheck.Finding) {
	h.idToFindings[f.OSV] = append(h.idToFindings[f.OSV], f)
}

func handleJSON(from io.Reader, to *osvHandler) error {
	dec := json.NewDecoder(from)
	for dec.More() {
		msg := govulncheck.Message{}
		// decode the next message in the stream
		if err := dec.Decode(&msg); err != nil {
			return err
		}
		if msg.Finding != nil {
			to.Finding(msg.Finding)
		}
	}

	return nil
}
