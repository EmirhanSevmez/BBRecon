package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

// --- Color Helpers ---
var (
	info     = color.New(color.FgCyan).PrintfFunc()
	success  = color.New(color.FgGreen).PrintfFunc()
	errColor = color.New(color.FgRed).PrintfFunc()
	yellow   = color.New(color.FgYellow).PrintfFunc()
)

// printMu serializes colored console output across goroutines so parallel
// recon steps don't interleave their log lines into garbage.
var printMu sync.Mutex

// --- Required Tools & Installation Paths ---
var requiredTools = map[string]string{
	"subfinder":   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
	"assetfinder": "github.com/tomnomnom/assetfinder@latest",
	"subzy":       "github.com/PentestPad/subzy@latest",
	"katana":      "github.com/projectdiscovery/katana/cmd/katana@latest",
	"amass":       "github.com/owasp-amass/amass/v4/cmd/amass@master",
	"dnsx":        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
}

// --- Auto-Install Function ---
func checkAndInstallDependencies() {
	fmt.Println("--------------------------------------------------")
	info("[*] System Check: Verifying required tools...\n")

	// Ensure GOPATH/bin is in PATH for this process
	homeDir, _ := os.UserHomeDir()
	goBin := filepath.Join(homeDir, "go", "bin")
	pathEnv := os.Getenv("PATH")
	if !strings.Contains(pathEnv, goBin) {
		os.Setenv("PATH", goBin+string(os.PathListSeparator)+pathEnv)
	}

	for tool, url := range requiredTools {
		// Check if the tool exists in the system PATH
		path, err := exec.LookPath(tool)

		if err != nil {
			yellow("[!] '%s' not found. Installing automatically... (This may take a while)\n", tool)

			// Run: go install github.com/...@latest
			cmd := exec.Command("go", "install", url)
			cmd.Stdout = nil // Keep screen clean
			cmd.Stderr = os.Stderr

			installErr := cmd.Run()
			if installErr != nil {
				errColor("[-] ERROR: Failed to install %s. Please install it manually.\n", tool)
				errColor("[-] Detail: %v\n", installErr)
			} else {
				success("[+] %s installed successfully.\n", tool)
			}
		} else {
			fmt.Printf("    -> %s: OK (%s)\n", tool, path)
		}
	}

	// Exception: httpx-toolkit (Rename httpx -> httpx-toolkit to avoid conflict)
	if _, err := exec.LookPath("httpx-toolkit"); err != nil {
		yellow("[!] 'httpx-toolkit' not found. Installing 'httpx' and renaming...\n")

		cmd := exec.Command("go", "install", "github.com/projectdiscovery/httpx/cmd/httpx@latest")
		cmd.Stdout = nil
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			errColor("[-] ERROR: Failed to install httpx: %v\n", err)
		} else {
			// Rename httpx.exe -> httpx-toolkit.exe
			homeDir, _ := os.UserHomeDir()
			goBin := filepath.Join(homeDir, "go", "bin")
			src := filepath.Join(goBin, "httpx.exe")
			dst := filepath.Join(goBin, "httpx-toolkit.exe")

			// Remove destination if exists (unlikely if lookpath failed, but good practice)
			os.Remove(dst)

			if err := os.Rename(src, dst); err != nil {
				errColor("[-] Failed to rename binary: %v\n", err)
				errColor("    Manually rename %s to %s\n", src, dst)
			} else {
				success("[+] httpx-toolkit installed and configured.\n")
			}
		}
	} else {
		fmt.Printf("    -> httpx-toolkit: OK\n")
	}

	fmt.Println("--------------------------------------------------\n")
}

// --- Download SecretFinder ---
func checkAndDownloadSecretFinder() {
	if _, err := os.Stat("secretfinder.py"); os.IsNotExist(err) {
		yellow("[!] 'secretfinder.py' not found. Downloading...\n")
		url := "https://raw.githubusercontent.com/m4ll0k/SecretFinder/master/SecretFinder.py"

		resp, err := http.Get(url)
		if err != nil {
			errColor("[-] Error downloading SecretFinder: %v\n", err)
			return
		}
		defer resp.Body.Close()

		out, err := os.Create("secretfinder.py")
		if err != nil {
			errColor("[-] Error creating file: %v\n", err)
			return
		}
		defer out.Close()

		_, err = io.Copy(out, resp.Body)
		if err != nil {
			errColor("[-] Error saving SecretFinder: %v\n", err)
			return
		}
		success("[+] SecretFinder downloaded successfully.\n")
	}
}

func printBanner() {
	color.HiMagenta(`
    ____  ____  ____
   / __ )/ __ )/ __ \___  _________  ____
  / __  / __  / /_/ / _ \/ ___/ __ \/ __ \
 / /_/ / /_/ / _, _/  __/ /__/ /_/ / / / /
/_____/_____/_/ |_|\___/\___/\____/_/ /_/

    Auto-Install & Recon Tool
    `)
	fmt.Println()
}

// --- Helper Functions ---

func runCommand(toolName string, args []string, outputFile string) {
	printMu.Lock()
	info("[*] Running: %s...\n", toolName)
	printMu.Unlock()

	cmd := exec.Command(toolName, args...)

	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			printMu.Lock()
			errColor("[-] File creation error (%s): %v\n", toolName, err)
			printMu.Unlock()
			return
		}
		defer f.Close()
		cmd.Stdout = f
	} else {
		cmd.Stdout = os.Stdout
	}

	cmd.Stderr = os.Stderr

	err := cmd.Run()

	printMu.Lock()
	defer printMu.Unlock()
	if err != nil {
		errColor("[-] Error (%s): %v\n", toolName, err)
	} else {
		success("[+] %s completed.\n", toolName)
	}
}

// runParallel fires every given task concurrently and waits for all of them
// to finish. Used for the independent subdomain-enumeration tools, since
// they don't depend on each other's output and running them sequentially
// just wastes wall-clock time.
func runParallel(tasks ...func()) {
	var wg sync.WaitGroup
	for _, t := range tasks {
		wg.Add(1)
		go func(fn func()) {
			defer wg.Done()
			fn()
		}(t)
	}
	wg.Wait()
}

func mergeAndUnique(filenames []string, outputFilename string) {
	yellow("[!] Merging files and removing duplicates...\n")

	uniqueMap := make(map[string]bool)
	counter := 0

	for _, filename := range filenames {
		f, err := os.Open(filename)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				uniqueMap[line] = true
			}
		}
		f.Close()
	}

	out, err := os.Create(outputFilename)
	if err != nil {
		return
	}
	defer out.Close()

	for domain := range uniqueMap {
		out.WriteString(domain + "\n")
		counter++
	}

	success("[+] Total Unique Subdomains: %d -> Saved to %s\n", counter, outputFilename)
}

// inScope reports whether a discovered host is actually within the tested
// target: either the bare domain itself, or a proper subdomain of it
// ("foo.example.com" qualifies for target "example.com", but
// "notexample.com" or "example.com.evil.net" must not).
func inScope(host, target string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	target = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(target), "."))
	return host == target || strings.HasSuffix(host, "."+target)
}

// filterScope splits a merged subdomain list into in-scope and out-of-scope
// files. Recon tools like subfinder/amass sometimes pull in unrelated hosts
// (shared CDN entries, lookalike domains, third-party infra) that must never
// be probed, crawled, or scanned — especially against programs like a VDP
// where testing anything outside the published scope is not authorized.
// Everything downstream of this function only ever sees the in-scope file.
func filterScope(inputFile, inScopeFile, outOfScopeFile, target string) int {
	yellow("[!] Applying scope guard (target: %s)...\n", target)

	in, err := os.Open(inputFile)
	if err != nil {
		errColor("[-] Scope guard: could not open %s: %v\n", inputFile, err)
		return 0
	}
	defer in.Close()

	inOut, err := os.Create(inScopeFile)
	if err != nil {
		errColor("[-] Scope guard: could not create %s: %v\n", inScopeFile, err)
		return 0
	}
	defer inOut.Close()

	outOut, err := os.Create(outOfScopeFile)
	if err != nil {
		errColor("[-] Scope guard: could not create %s: %v\n", outOfScopeFile, err)
		return 0
	}
	defer outOut.Close()

	inCount, outCount := 0, 0
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if inScope(line, target) {
			inOut.WriteString(line + "\n")
			inCount++
		} else {
			outOut.WriteString(line + "\n")
			outCount++
		}
	}

	success("[+] Scope guard: %d in-scope, %d out-of-scope (-> %s)\n", inCount, outCount, outOfScopeFile)
	if outCount > 0 {
		yellow("[!] %d out-of-scope host(s) were EXCLUDED from all further testing. Review %s before reporting any of them.\n", outCount, outOfScopeFile)
	}

	return inCount
}

func extractJS(inputFile string, outputFile string) {
	yellow("[!] Extracting .js files from crawl data...\n")

	f, err := os.Open(inputFile)
	if err != nil {
		return
	}
	defer f.Close()

	out, err := os.Create(outputFile)
	if err != nil {
		return
	}
	defer out.Close()

	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, ".js") {
			out.WriteString(line + "\n")
			count++
		}
	}
	success("[+] Found %d JS files -> Saved to %s\n", count, outputFile)
}

func runSecretFinder(jsFileList string) {
	yellow("[!] Starting SecretFinder (Python)...\n")

	// Check if secretfinder.py exists
	if _, err := os.Stat("secretfinder.py"); os.IsNotExist(err) {
		errColor("[-] ERROR: 'secretfinder.py' not found in the current directory.\n")
		return
	}

	f, err := os.Open(jsFileList)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		jsUrl := scanner.Text()
		fmt.Printf("   > Analyzing: %s\n", jsUrl)

		cmd := exec.Command("python3", "secretfinder.py", "-i", jsUrl, "-o", "cli")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Run()
	}
}

// --- Main Execution ---

func main() {
	// 0. Check and Install Dependencies
	checkAndInstallDependencies()
	checkAndDownloadSecretFinder()

	printBanner()
	time.Sleep(1 * time.Second)

	domainPtr := flag.String("d", "", "Target domain (e.g., example.com)")
	flag.Parse()

	if *domainPtr == "" {
		errColor("[-] Error: Domain is required.\n")
		info("Usage: go run main.go -d target.com\n")
		os.Exit(1)
	}

	target := *domainPtr

	// Creates results directory: results/<target>
	outputDir := filepath.Join("results", target)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		errColor("[-] Error creating output directory: %v\n", err)
		os.Exit(1)
	}
	success("[+] Results will be saved to: %s\n", outputDir)

	subfinderFile := filepath.Join(outputDir, "subfinder.txt")
	assetsFile := filepath.Join(outputDir, "assets.txt")
	amassFile := filepath.Join(outputDir, "amass.txt")
	mergedFile := filepath.Join(outputDir, "sub_all.txt")
	inScopeFile := filepath.Join(outputDir, "sub.txt")
	outOfScopeFile := filepath.Join(outputDir, "out_of_scope.txt")
	dnsxFile := filepath.Join(outputDir, "dnsx.txt")
	liveFile := filepath.Join(outputDir, "live.txt")
	statusFile := filepath.Join(outputDir, "status.txt")
	katanaFile := filepath.Join(outputDir, "katana.txt")
	jsFile := filepath.Join(outputDir, "jsfiles.txt")

	// 1. Subdomain Discovery — subfinder, assetfinder and amass are
	// independent of each other, so run them concurrently instead of
	// burning wall-clock time waiting on each one in turn.
	// amass runs in -passive mode only: no active brute-forcing, which
	// keeps traffic footprint low and appropriate for programs (like
	// VDPs) that don't want aggressive scanning.
	info("[*] Running subfinder, assetfinder and amass in parallel...\n")
	runParallel(
		func() {
			runCommand("subfinder", []string{"-d", target, "-o", subfinderFile}, "")
		},
		func() {
			runCommand("assetfinder", []string{"--subs-only", target}, assetsFile)
		},
		func() {
			runCommand("amass", []string{"enum", "-passive", "-d", target, "-o", amassFile}, "")
		},
	)

	// 2. Merge & Deduplicate (all three sources)
	mergeAndUnique([]string{subfinderFile, assetsFile, amassFile}, mergedFile)

	// 3. Scope Guard — drop anything that isn't actually target or a
	// subdomain of target before any probing/crawling/scanning touches it.
	inCount := filterScope(mergedFile, inScopeFile, outOfScopeFile, target)
	if inCount == 0 {
		errColor("[-] No in-scope hosts found after filtering. Stopping.\n")
		os.Exit(1)
	}

	// 4. DNS resolution + wildcard detection on the in-scope set only.
	// -wd flags the target so dnsx can filter out wildcard-DNS noise
	// (large orgs are prone to this, and wildcard entries otherwise show
	// up as a pile of "alive" subdomains that aren't real hosts).
	runCommand("dnsx", []string{"-l", inScopeFile, "-wd", target, "-o", dnsxFile}, "")

	// 5. Live Check (Probing) — in-scope only
	runCommand("httpx-toolkit", []string{"-l", inScopeFile, "-o", liveFile}, "")

	// 6. Detailed Scan — in-scope only
	runCommand("httpx-toolkit", []string{
		"-l", inScopeFile,
		"-title", "-sc", "-cl", "-location", "-fr",
		"-o", statusFile,
	}, "")

	// 7. Subdomain Takeover Check — in-scope only
	runCommand("subzy", []string{"run", "--targets", inScopeFile}, "")

	// 8. Crawling (Katana) — in-scope, live hosts only
	runCommand("katana", []string{"-u", liveFile, "-o", katanaFile}, "")

	// 9. JS Extraction
	extractJS(katanaFile, jsFile)

	// 10. Secret Analysis
	runSecretFinder(jsFile)

	fmt.Println()
	color.HiGreen("[!!!] All Recon Tasks Completed Successfully! [!!!]")
}
