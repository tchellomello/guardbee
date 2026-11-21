package main

// The probe image catalog: which images a connectivity test may inject. Like
// the Policy Editor templates it is data, not code — probes/images.yaml is
// embedded as the default and "ui --probe-images-file" replaces it. The
// browser only ever picks an entry by id; the image reference itself never
// comes from a request, so nothing in the browser can choose what runs
// inside a workload beyond what the operator started the server with.

import (
	"embed"
	"fmt"
	"os"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"
)

//go:embed probes/images.yaml
var defaultProbeImagesFS embed.FS

type probeImage struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Image       string   `json:"image"`
	Protocols   []string `json:"protocols"`
	Description string   `json:"description,omitempty"`
}

// pinned reports a digest reference: GuardBee pulls tag-only images on every
// test (PullAlways), so only a digest guarantees two tests ran the same code.
func (p probeImage) pinned() bool { return strings.Contains(p.Image, "@sha256:") }

func (p probeImage) supports(protocol string) bool {
	for _, have := range p.Protocols {
		if have == protocol {
			return true
		}
	}
	return false
}

// cliProbeImage is the one-entry catalog "--probe-image" has always meant.
// Its protocols are unknown, so both are offered; a missing runtime still
// ends as exit 126/127, reported inconclusive, never guessed.
func cliProbeImage(image string) probeImage {
	name, _, _ := strings.Cut(image, "@")
	name = name[strings.LastIndex(name, "/")+1:]
	if len(name) > 64 {
		name = name[:64]
	}
	return probeImage{ID: "cli", Name: name, Image: image, Protocols: []string{"TCP", "UDP"}, Description: "Set with --probe-image"}
}

// loadProbeImages reads the catalog from path, or the built-in one when path
// is empty. Unknown fields are rejected so a typo ("protocol:") fails loudly
// at startup instead of silently offering an image for nothing.
func loadProbeImages(path string) ([]probeImage, error) {
	var raw []byte
	var err error
	if path == "" {
		raw, err = defaultProbeImagesFS.ReadFile("probes/images.yaml")
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	var doc struct {
		Images []probeImage `json:"images"`
	}
	if err := yaml.UnmarshalStrict(raw, &doc); err != nil {
		return nil, fmt.Errorf("parsing probe image catalog: %w", err)
	}
	if err := validateProbeImages(doc.Images); err != nil {
		return nil, err
	}
	return doc.Images, nil
}

func validateProbeImages(images []probeImage) error {
	if len(images) == 0 {
		return fmt.Errorf("probe image catalog has no images")
	}
	seen := map[string]bool{}
	for i, img := range images {
		where := fmt.Sprintf("probe image %d (%q)", i+1, img.ID)
		switch {
		case len(validation.IsDNS1123Label(img.ID)) > 0:
			return fmt.Errorf("%s: id must be a lowercase DNS label", where)
		case seen[img.ID]:
			return fmt.Errorf("%s: duplicate id", where)
		case strings.TrimSpace(img.Name) == "" || len(img.Name) > 64:
			return fmt.Errorf("%s: name must be 1-64 characters", where)
		case !validProbeImage(img.Image):
			return fmt.Errorf("%s: image must be repository:tag or repository[:tag]@sha256:<64 lowercase hex digits>", where)
		case len(img.Description) > 280:
			return fmt.Errorf("%s: description must be at most 280 characters", where)
		case len(img.Protocols) == 0:
			return fmt.Errorf("%s: protocols must list TCP and/or UDP", where)
		}
		protocols := map[string]bool{}
		for _, p := range img.Protocols {
			if p != "TCP" && p != "UDP" || protocols[p] {
				return fmt.Errorf("%s: protocols must be TCP and/or UDP, each once", where)
			}
			protocols[p] = true
		}
		seen[img.ID] = true
	}
	return nil
}
