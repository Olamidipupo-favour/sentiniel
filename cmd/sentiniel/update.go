package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Olamidipupo-favour/sentiniel"
)

func runUpdate(args []string) {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	var check, force bool
	fs.BoolVar(&check, "check", false, "report the latest release without installing it")
	fs.BoolVar(&force, "force", false, "reinstall even when the version already matches")
	fs.Parse(args)

	client, err := sentiniel.NewGitHubClient("")
	if err != nil {
		client = &sentiniel.GitHubClient{HTTP: &http.Client{Timeout: 60 * time.Second}}
	}
	tag, assets, err := client.LatestRelease()
	if err != nil {
		fatal(err.Error())
	}
	latest := strings.TrimPrefix(tag, "v")
	current := strings.TrimPrefix(buildVersion(), "v")
	if check {
		fmt.Printf("installed %s, latest %s\n", current, latest)
		return
	}
	if latest == current && !force {
		fmt.Printf("sentiniel %s is up to date\n", current)
		return
	}
	archiveName, archiveURL := pickAsset(assets, latest, runtime.GOOS, runtime.GOARCH)
	if archiveURL == "" {
		fatal(fmt.Sprintf("release %s has no build for %s/%s", tag, runtime.GOOS, runtime.GOARCH))
	}
	checksumsURL := ""
	for _, asset := range assets {
		if asset.Name == "checksums.txt" {
			checksumsURL = asset.URL
		}
	}
	if checksumsURL == "" {
		fatal("release has no checksums.txt; refusing to install an unverified binary")
	}
	checksums, err := download(checksumsURL)
	if err != nil {
		fatal(err.Error())
	}
	want, ok := checksumFor(string(checksums), archiveName)
	if !ok {
		fatal("checksums.txt does not list " + archiveName)
	}
	archive, err := download(archiveURL)
	if err != nil {
		fatal(err.Error())
	}
	got := sha256.Sum256(archive)
	if hex.EncodeToString(got[:]) != want {
		fatal(fmt.Sprintf("checksum mismatch for %s; not installing", archiveName))
	}
	binary, err := binaryFrom(archiveName, archive)
	if err != nil {
		fatal(err.Error())
	}
	path, err := install(binary)
	if err != nil {
		fatal(err.Error())
	}
	if path == "" {
		return
	}
	fmt.Printf("updated sentiniel %s -> %s (%s)\n", current, latest, path)
}

func pickAsset(assets []sentiniel.ReleaseAsset, version, goos, goarch string) (name, url string) {
	for _, asset := range assets {
		if strings.HasSuffix(asset.Name, "_"+version+"_"+goos+"_"+goarch+".tar.gz") ||
			strings.HasSuffix(asset.Name, "_"+version+"_"+goos+"_"+goarch+".zip") {
			return asset.Name, asset.URL
		}
	}
	return "", ""
}

func checksumFor(checksums, name string) (string, bool) {
	for _, line := range strings.Split(checksums, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == name {
			return fields[0], true
		}
	}
	return "", false
}

func download(url string) ([]byte, error) {
	res, err := (&http.Client{Timeout: 120 * time.Second}).Get(url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: %s", url, res.Status)
	}
	return io.ReadAll(res.Body)
}

func binaryFrom(archiveName string, data []byte) ([]byte, error) {
	if strings.HasSuffix(archiveName, ".zip") {
		reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, err
		}
		for _, file := range reader.File {
			if filepath.Base(file.Name) == "sentiniel.exe" {
				rc, err := file.Open()
				if err != nil {
					return nil, err
				}
				defer rc.Close()
				return io.ReadAll(rc)
			}
		}
		return nil, errors.New("release archive has no sentiniel.exe")
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tarReader := tar.NewReader(gz)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if filepath.Base(header.Name) == "sentiniel" {
			return io.ReadAll(tarReader)
		}
	}
	return nil, errors.New("release archive has no sentiniel binary")
}

// install replaces the running executable and returns its path, or "" when the OS blocks it.
func install(binary []byte) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	tmp, err := os.CreateTemp(filepath.Dir(exe), ".sentiniel-update-")
	if err != nil {
		return "", err
	}
	if _, err := tmp.Write(binary); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	if err := os.Chmod(tmp.Name(), 0755); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	if err := os.Rename(tmp.Name(), exe); err != nil {
		// Windows cannot replace a running executable.
		if runtime.GOOS == "windows" {
			fmt.Printf("downloaded the new binary to %s; move it over %s after closing this shell\n", tmp.Name(), exe)
			return "", nil
		}
		os.Remove(tmp.Name())
		return "", err
	}
	return exe, nil
}
