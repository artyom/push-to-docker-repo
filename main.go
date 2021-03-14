// push-to-docker-repo is an example program demonstrating how to construct and
// push Docker images to a docker repository only using the Go standard
// library.
//
// It is an approximate equivalent of packing static linux/amd64 Go binary to a
// "FROM scratch" docker container, and pushing this container to a docker
// repository.
//
// This program reads registry authentication token from
// ${HOME}/.docker/config.json file.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) != 0 && os.Args[0] == insideContainerPath &&
		os.Getenv(insideContainerEnv) == insideContainerEnvValue {
		log.Println("Hello from inside the container!")
		return
	}
	args := runArgs{}
	flag.Func("image", "docker image name in `domain.tld/name:tag` format", args.imageSpec.fromString)
	flag.StringVar(&args.bin, "bin", "", "`path` to statically compiled linux/amd64 file to pack into container;"+
		"\nif empty, program will use its own binary")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err := run(ctx, args); err != nil {
		log.Fatal(err)
	}
}

type runArgs struct {
	imageSpec imageSpec // full docker image name
	bin       string    // path to binary to pack into an image
}

func run(ctx context.Context, args runArgs) error {
	if args.imageSpec == (imageSpec{}) {
		return errors.New("please set image spec with an -image flag")
	}
	authFile := os.ExpandEnv(filepath.FromSlash("${HOME}/.docker/config.json"))
	auth, err := readAuth(authFile, args.imageSpec.Domain)
	if err != nil {
		return fmt.Errorf("credentials read: %w", err)
	}
	if args.bin == "" {
		if args.bin, err = os.Executable(); err != nil {
			return fmt.Errorf("cannot figure out process executable path: %w", err)
		}
	}
	tgz, tgzInfo, err := archiveBinary(args.bin)
	if err != nil {
		return fmt.Errorf("creating an image layer: %w", err)
	}
	if err := uploadBlob(ctx, args.imageSpec, auth, tgz); err != nil {
		return fmt.Errorf("uploading an image layer: %w", err)
	}
	manifest, err := putImageConfig(ctx, args.imageSpec, auth, tgzInfo)
	if err != nil {
		return fmt.Errorf("config upload: %w", err)
	}
	if err := putManifest(ctx, args.imageSpec, auth, manifest); err != nil {
		return fmt.Errorf("publishing manifest: %w", err)
	}
	return nil
}

// putImageConfig generates an image config from layer metadata, uploads this
// config as a separate blob, and returns json-serialized manifest that
// describes both layer and config.
func putImageConfig(ctx context.Context, img imageSpec, auth string, tgzInfo *layerMetadata) (json.RawMessage, error) {
	now := time.Now().UTC()
	runConfig := struct {
		Arch   string          `json:"architecture"`
		OS     string          `json:"os"`
		Time   time.Time       `json:"created"`
		Config containerConfig `json:"config"`
		Rootfs struct {
			Type  string   `json:"type"`
			Diffs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}{
		Arch: "amd64",
		OS:   "linux",
		Time: now,
		Config: containerConfig{
			Env:         []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
			Cmd:         []string{insideContainerPath},
			ArgsEscaped: true,
			WorkingDir:  "/",
		},
	}
	runConfig.Rootfs.Type = "layers"
	runConfig.Rootfs.Diffs = []string{tgzInfo.innerDigest}
	body, err := json.Marshal(&runConfig)
	if err != nil {
		return nil, err
	}
	configDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(body))

	if err := uploadBlob(ctx, img, auth, body); err != nil {
		return nil, err
	}

	type blobInfo struct {
		MediaType string `json:"mediaType"`
		Size      int    `json:"size"`
		Digest    string `json:"digest"`
	}
	manifest := struct {
		Version   int        `json:"schemaVersion"`
		MediaType string     `json:"mediaType"`
		Config    blobInfo   `json:"config"`
		Layers    []blobInfo `json:"layers"`
	}{
		Version:   2,
		MediaType: "application/vnd.docker.distribution.manifest.v2+json",
		Config: blobInfo{
			MediaType: "application/vnd.docker.container.image.v1+json",
			Size:      len(body),
			Digest:    configDigest,
		},
		Layers: []blobInfo{
			{
				MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
				Size:      tgzInfo.outerSize,
				Digest:    tgzInfo.outerDigest,
			},
		},
	}
	return json.Marshal(&manifest)
}

// putManifest uploads a v2 manifest — a final step in publishing new image.
// See https://docs.docker.com/registry/spec/api/#put-manifest
func putManifest(ctx context.Context, img imageSpec, auth string, body json.RawMessage) error {
	u := &url.URL{
		Scheme: "https",
		Host:   img.Domain,
		Path:   path.Join("/v2", img.Name, "manifests", img.Tag),
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b := new(bytes.Buffer)
		io.Copy(b, io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("unexpected status on manifest put %q: %v\n%s", req.URL, resp.Status, b.Bytes())
	}
	return nil
}

// uploadBlob uploads given blob to the registry.
func uploadBlob(ctx context.Context, img imageSpec, auth string, body []byte) error {
	uploadURL, err := getUploadLocation(ctx, img, auth)
	if err != nil {
		return err
	}
	if strings.ContainsRune(uploadURL, '?') {
		return fmt.Errorf("upload url contains '?': %q", uploadURL)
	}
	uploadURL += fmt.Sprintf("?digest=sha256:%x", sha256.Sum256(body))
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, uploadURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(len(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b := new(bytes.Buffer)
		io.Copy(b, io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("unexpected status on blob upload %q: %v\n%s", req.URL, resp.Status, b.Bytes())
	}
	return nil
}

// getUploadLocation retrieves an upload location for a new blob from registry
// API. See https://docs.docker.com/registry/spec/api/#starting-an-upload
func getUploadLocation(ctx context.Context, img imageSpec, auth string) (string, error) {
	u := &url.URL{
		Scheme: "https",
		Host:   img.Domain,
		Path:   path.Join("/v2", img.Name, "blobs/uploads") + "/",
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Basic "+auth)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		b := new(bytes.Buffer)
		io.Copy(b, io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("unexpected status on %s %s: %v\n%s", req.Method, req.URL.Path, resp.Status, b.Bytes())
	}
	location := resp.Header.Get("Location")
	if location == "" {
		return "", errors.New("response has no valid location")
	}
	return location, nil
}

type layerMetadata struct {
	outerDigest string // compressed blob digest
	innerDigest string // uncompressed blob digest
	outerSize   int    // uncompressed blob size
}

// archiveBinary returns a tar.gz archive holding given binary, plus some
// metadata describing archive digests.
func archiveBinary(exe string) ([]byte, *layerMetadata, error) {
	f, err := os.Open(exe)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	outerDigest, innerDigest := sha256.New(), sha256.New()
	buf := new(bytes.Buffer)
	gw := gzip.NewWriter(io.MultiWriter(buf, outerDigest))
	tw := tar.NewWriter(io.MultiWriter(gw, innerDigest))
	if err := tw.WriteHeader(&tar.Header{
		Name:    strings.TrimPrefix(insideContainerPath, "/"),
		Mode:    0755,
		ModTime: fi.ModTime(),
		Size:    fi.Size(),
	}); err != nil {
		return nil, nil, err
	}
	if _, err := io.Copy(tw, f); err != nil {
		return nil, nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, nil, err
	}
	return buf.Bytes(), &layerMetadata{
		outerDigest: fmt.Sprintf("sha256:%x", outerDigest.Sum(nil)),
		innerDigest: fmt.Sprintf("sha256:%x", innerDigest.Sum(nil)),
		outerSize:   buf.Len(),
	}, nil
}

// readAuth parses user docker config file and returns authorization token for
// given domain.
func readAuth(path, domain string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	tmp := struct {
		Entries map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}{}
	if err := json.Unmarshal(b, &tmp); err != nil {
		return "", err
	}
	entry, ok := tmp.Entries[domain]
	if !ok {
		return "", errors.New("no auth entry found for domain")
	}
	return entry.Auth, nil
}

type containerConfig struct {
	Env         []string
	Cmd         []string
	ArgsEscaped bool
	WorkingDir  string
}

// imageSpec describes full docker image name in domain.tld/name:tag format
// (e.g. public.ecr.aws/amazonlinux/amazonlinux:latest)
type imageSpec struct {
	Domain string // public.ecr.aws
	Name   string // amazonlinux/amazonlinux
	Tag    string // latest
}

func (spec *imageSpec) fromString(s string) error {
	slashIndex := strings.IndexRune(s, '/')
	colonIndex := strings.IndexRune(s, ':')
	colonCount := strings.Count(s, ":")
	if colonCount != 1 || colonIndex < slashIndex || slashIndex == -1 || colonIndex == -1 {
		return fmt.Errorf("invalid image spec: %q, must be in domain.tld/name:tag format", s)
	}
	tag := s[colonIndex+1:]
	name := path.Clean(s[slashIndex+1 : colonIndex])
	domain := s[:slashIndex]
	if domain == "" || name == "" || tag == "" {
		return fmt.Errorf("invalid image spec: %q, must be in domain.tld/name:tag format", s)
	}
	for _, r := range tag {
		switch {
		case r == '.', r == '-', '0' <= r && r <= '9', 'a' <= r && r <= 'z', 'A' <= r && r <= 'Z':
		default:
			return fmt.Errorf("image tag %q contains invalid symbols", tag)
		}
	}
	for _, r := range name {
		switch {
		case r == '.', r == '-', r == '/', '0' <= r && r <= '9', 'a' <= r && r <= 'z', 'A' <= r && r <= 'Z':
		default:
			return fmt.Errorf("image name %q contains invalid symbols", name)
		}
	}
	for _, r := range domain {
		switch {
		case r == '.', r == '-', '0' <= r && r <= '9', 'a' <= r && r <= 'z', 'A' <= r && r <= 'Z':
		default:
			return fmt.Errorf("image domain %q contains invalid symbols", domain)
		}
	}
	spec.Domain = domain
	spec.Name = name
	spec.Tag = tag
	return nil
}

// insideContainerPath is an absolute path of a binary inside docker image
const insideContainerPath = "/hello-from-container"

const insideContainerEnv = "RUNS_IN_CONTAINER" // env to set inside the container
const insideContainerEnvValue = "1"            // env value
