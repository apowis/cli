package i18n

import "github.com/MakeNowJust/heredoc/v2"

type Copy struct {
	AboutInfo       string
	InteractiveOnly string
	RootLong        string

	AuthShort                   string
	AuthStatusShort             string
	AuthStatusLong              string
	AuthLoginShort              string
	AuthLoginLong               string
	AuthLoginExample            string
	AuthLoginErrorCI            string
	AuthLogoutShort             string
	AuthLogoutTokenRemoved      string
	AuthLogoutErrorFailed       string
	AuthLogoutErrorInvalidToken string

	OfflineStatusShort string
	OfflineStatusLong  string

	AuthLoginToken string
	AuthLoginWeb   string

	FlagSaveResults      string
	FlagOutputJson       string
	FlagSpecifyFile      string
	FlagSpecifySbomFile  string
	FlagSpecifySbomInput string
	FlagSpecifySbomOnly  string
	FlagIncludeCpes      string
	FlagEnrich           string
	SavingResultsStart   string
	SavingResultsEnd     string

	TokenShort string

	ListTokensShort string
	ListTokensFull  string

	BrowseTokensShort string
	BrowseTokens      string

	CreateTokenShort         string
	CreateTokenLabelRequired string
	CreateTokenSuccess       string

	RemoveTokenShort      string
	RemoveTokenSuccess    string
	RemoveTokenIDRequired string

	IndicesShort string

	ListIndicesShort  string
	ListIndicesSearch string
	ListIndicesFull   string

	BrowseIndicesShort  string
	BrowseIndicesSearch string
	BrowseIndicesFull   string

	IndexShort            string
	IndexListShort        string
	IndexBrowseShort      string
	IndexErrorRequired    string
	IndexFlagFullResponse string

	AdvisoryShort       string
	AdvisoryFeedsShort  string
	AdvisoryFeedsSearch string
	AdvisoryFeedsFull   string
	AdvisoryListShort   string
	AdvisoryBrowseShort string
	AdvisoryFound       string

	NvdShort            string
	NvdCvesShort        string
	NvdCveHistoryShort  string
	NvdCpesShort        string
	NvdCpeMatchShort    string
	NvdSourceShort      string
	NvdFound            string
	NvdNextCursor       string
	NvdFlagFullResponse string

	TargetIntelShort               string
	TargetIntelLong                string
	TargetIntelExample             string
	TargetIntelAuthShort           string
	TargetIntelAuthLoginShort      string
	TargetIntelAuthLoginLong       string
	TargetIntelAuthLoginErrorCI    string
	TargetIntelAuthLogoutShort     string
	TargetIntelAuthStatusShort     string
	TargetIntelDatasetsShort       string
	TargetIntelDatasetsListShort   string
	TargetIntelTablesShort         string
	TargetIntelTablesListShort     string
	TargetIntelTablesDescribeShort string
	TargetIntelQueryShort          string
	TargetIntelQueryLong           string
	TargetIntelQueryExample        string
	TargetIntelEstimateShort       string
	TargetIntelEstimateLong        string
	TargetIntelCvesShort           string
	TargetIntelCvesLong            string
	TargetIntelCvesExample         string
	TargetIntelProductShort        string
	TargetIntelProductLong         string
	TargetIntelProductExample      string
	TargetIntelHostShort           string
	TargetIntelHostLong            string
	TargetIntelHostExample         string
	TargetIntelServiceShort        string
	TargetIntelServiceLong         string
	TargetIntelServiceHTTPShort    string
	TargetIntelServiceHTTPLong     string
	TargetIntelServiceHTTPExample  string

	BackupShort            string
	BackupLong             string
	BackupListShort        string
	BackupListFull         string
	BackupUrlShort         string
	BackupDownloadShort    string
	BackupDownloadInfo     string
	BackupDownloadProgress string
	BackupDownloadComplete string

	BackupAdvisoryShort         string
	BackupAdvisoryOverwrite     string
	BackupAdvisoryListShort     string
	BackupAdvisoryListFull      string
	BackupAdvisoryUrlShort      string
	BackupAdvisoryDownloadShort string
	BackupAdvisoryDownloadInfo  string
	BackupAdvisoryErrorRequired string
	BackupAdvisoryUnavailable   string

	CpeShort               string
	CpeExample             string
	CpeNoCves              string
	CpeCvesFound           string
	CpeErrorSchemeRequired string

	PurlShort               string
	PurlExample             string
	PurlNoVulns             string
	PurlVulnFound           string
	PurlVulnsFound          string
	PurlErrorSchemeRequired string

	RuleShort                 string
	RuleErrorRequired         string
	RuleExample               string
	RuleErrorRuleNameRequired string

	TagShort                string
	TagExample              string
	TagErrorTagNameRequired string

	PdnsShort                 string
	PdnsExample               string
	PdnsErrorListNameRequired string

	ScanShort                   string
	ScanExample                 string
	ScanErrorDirectoryRequired  string
	ScanSbomStart               string
	ScanSbomLoad                string
	ScanSbomEnd                 string
	ScanSbomLoaded              string
	ScanExtractPurlStart        string
	ScanExtractPurlEnd          string
	ScanScanPurlStart           string
	ScanScanPurlStartOffline    string
	ScanScanPurlProgress        string
	ScanScanPurlProgressOffline string
	ScanScanPurlEnd             string
	ScanScanPurlEndPartial      string
	ScanUnprocessed             string
	ScanUnprocessedMore         string
	ScanScanPurlEndOffline      string
	ScanExtractCpeStart         string
	ScanExtractCpeEnd           string
	ScanScanCpeStartOffline     string
	ScanScanCpeProgressOffline  string
	ScanScanCpeEndOffline       string

	ScanVulnMetaStart string
	ScanVulnMetaEnd   string

	ScanVulnOfflineMetaStart string
	ScanVulnOfflineMetaEnd   string

	ScanVulnOfflineMetaUnavailable string

	ScanNoCvesFound string
	ScanBenchmark   string

	UpgradeShort string
	UpgradeLong  string

	UpgradeLatestShort string
	UpgradeLatestLong  string

	UpgradeStatusShort string
	UpgradeStatusLong  string

	ErrorNoToken      string
	ErrorUnauthorized string
}

var C Copy

var En = Copy{
	AboutInfo: heredoc.Doc(`
					The VulnCheck CLI is a command-line interface for the VulnCheck API
					For more information on our products, please visit https://vulncheck.com
					For API Documentation, please visit https://docs.vulncheck.com
	`),
	InteractiveOnly: "This command is interactive and cannot run in a CI environment, please try %s instead",
	RootLong:        "Work seamlessly with the VulnCheck API.",

	AuthShort:       "Authenticate vulncheck with the VulnCheck portal",
	AuthStatusShort: "Check authentication status",
	AuthStatusLong:  "Check if you're currently authenticated and if so, display the account information",
	AuthLoginShort:  "Authenticate with the VulnCheck portal",
	AuthLoginLong: heredoc.Docf(`
			Authenticate with a VulnCheck account.

			The default authentication mode is a web-based browser flow.

			Alternatively, use %[1]stoken%[1]s to specify an issued token directly.

			Alternatively, vulncheck will use the authentication token found in the %[1]sVULNCHECK_API_TOKEN%[1]s environment variable.
			This method is most suitable for "headless" use of vulncheck such as in automation.
		`, "`"),
	AuthLoginExample: heredoc.Doc(`
			# Start interactive authentication
			$ vulncheck auth login

			# Authenticate with vulncheck.com by passing in a token
			$ vulncheck auth login token vulncheck_******************
	`),
	AuthLoginErrorCI: "This command is interactive and cannot be run in a CI environment, use the VULNCHECK_API_TOKEN environment variable instead",

	AuthLoginToken: "Connect a VulnCheck account using an authentication token",
	AuthLoginWeb:   "Log in with a VulnCheck account using a web browser",

	AuthLogoutShort:             "Invalidate and remove your current authentication token",
	AuthLogoutTokenRemoved:      "Token invalidated and removed",
	AuthLogoutErrorFailed:       "Failed to remove token",
	AuthLogoutErrorInvalidToken: "Token was invalid, removing from config",

	FlagSaveResults:      "Save Results as a file",
	FlagOutputJson:       "Output JSON Results",
	FlagSpecifyFile:      "Specify the file to save the results to",
	FlagSpecifySbomFile:  "Specify the file to save your SBOM scan to",
	FlagSpecifySbomInput: "Specify an existing SBOM file to scan instead of creating one from a folder",
	FlagSpecifySbomOnly:  "Do not run a scan and only create a SBOM file",
	FlagIncludeCpes:      "Include and Scan CPEs",
	FlagEnrich:           "Enrich the generated SBOM with additional metadata from local and online sources (e.g. proxy.golang.org, Maven Central, NPM, PyPI). Comma-separated scopes; supported values: all, golang, java, javascript, python. Prefix with '-' to exclude (e.g. all,-java). Off by default; enabling adds runtime cost and requires network access. Cannot be combined with --offline or --sbom-input-file.",
	SavingResultsStart:   "Saving Results to %s",
	SavingResultsEnd:     "Results saved to %s",

	TokenShort: "Manage Tokens",

	ListTokensShort: "List tokens",
	ListTokensFull:  "Listing %d tokens",
	BrowseTokens:    "Browsing %d tokens, ESC or q to quit, c to create a token",

	BrowseTokensShort: "Browse tokens interactively",

	CreateTokenShort:         "Create a token",
	CreateTokenSuccess:       "Token %s created successfully: %s",
	CreateTokenLabelRequired: "Token Label missing or invalid",

	RemoveTokenShort:      "Remove a token",
	RemoveTokenSuccess:    "Token %s removed successfully",
	RemoveTokenIDRequired: "Token ID missing or invalid",

	IndicesShort: "View indices",

	ListIndicesShort:  "List indices",
	ListIndicesSearch: "Listing %d indices searching for \"%s\"",
	ListIndicesFull:   "Listing %d indices",

	BrowseIndicesShort:  "Browse indices",
	BrowseIndicesSearch: "Listing %d indices searching for \"%s\"",
	BrowseIndicesFull:   "Listing %d indices",

	IndexShort:            "Browse or list an index",
	IndexListShort:        "List documents of a specified index",
	IndexBrowseShort:      "Browse documents of an index interactively",
	IndexErrorRequired:    "index name is required",
	IndexFlagFullResponse: "Output full response",

	AdvisoryShort:       "Query advisories in CVE Record Format 5.2 (api /v4)",
	AdvisoryFeedsShort:  "List the advisory feeds available to filter by (GET /v4/advisory/list)",
	AdvisoryFeedsSearch: "Listing %d advisory feeds searching for \"%s\"",
	AdvisoryFeedsFull:   "Listing %d advisory feeds",
	AdvisoryListShort:   "List advisory records (GET /v4/advisory)",
	AdvisoryBrowseShort: "Browse advisory records interactively (GET /v4/advisory)",
	AdvisoryFound:       "%d of %d advisory records",

	TargetIntelShort: "Query VulnCheck Target Intelligence scan data in BigQuery",
	TargetIntelLong: heredoc.Doc(`
		Query VulnCheck Target Intelligence data in BigQuery.

		Every query runs under a bytes-billed cap of --max-cost (default $1.00,
		or VC_TI_MAX_COST). BigQuery enforces the cap on the bytes actually
		read: a job that would bill more fails before anything is charged, and
		the command exits 7. "estimate" and --dry-run give a free estimate
		without running anything.

		Authenticate with a Google account using "target-intel auth login", or set
		VC_TI_CREDENTIALS to a service-account key file.
	`),
	TargetIntelExample: heredoc.Doc(`
		$ vulncheck target-intel auth login
		$ vulncheck target-intel datasets list
		$ vulncheck target-intel tables describe anchorbreaker_prod.timeline
		$ vulncheck target-intel cves --cves CVE-2024-6387 --days 30
		$ vulncheck target-intel cves --cves CVE-2024-6387 --counts
		$ vulncheck target-intel cves --top --kev
		$ vulncheck target-intel product --product netscaler --group-by version
		$ vulncheck target-intel host 1.2.3.4
		$ vulncheck target-intel service http --title fortigate
		$ vulncheck target-intel estimate --from-file big-join.sql
		$ vulncheck target-intel query --limit 10 --query "SELECT ip, port FROM anchorbreaker_prod.timeline WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 DAY) LIMIT 10"
	`),
	TargetIntelAuthShort:           "Manage Target Intelligence (Google) credentials",
	TargetIntelAuthLoginShort:      "Authenticate to the Target Intelligence warehouse with a Google account",
	TargetIntelAuthLoginLong:       "Opens a browser to sign in with Google, the same way gcloud auth login does, and stores a refresh token in the config directory. Use --no-browser to print the URL instead, for a machine without a browser.",
	TargetIntelAuthLoginErrorCI:    "This command is interactive and cannot be run in a CI environment; set VC_TI_CREDENTIALS to a service-account key file, or pass --no-browser and complete the login from another machine",
	TargetIntelAuthLogoutShort:     "Remove stored Target Intelligence credentials",
	TargetIntelAuthStatusShort:     "Show the credential source, principal, billing project and cost limit",
	TargetIntelDatasetsShort:       "List available datasets",
	TargetIntelDatasetsListShort:   "List the datasets in the billing project",
	TargetIntelTablesShort:         "List and describe tables",
	TargetIntelTablesListShort:     "List the tables and views in a dataset",
	TargetIntelTablesDescribeShort: "Show a table's schema, size, partition and cluster keys (free)",
	TargetIntelQueryShort:          "Run a read-only SQL query under a cost cap",
	TargetIntelQueryLong: heredoc.Doc(`
		Run a read-only SQL query against Target Intelligence.

		The query runs with --max-cost sent to BigQuery as maximumBytesBilled:
		a job that would bill more than the cap fails before anything is
		charged and the command exits 7 (cost_limit_exceeded) with the value
		that would allow it. --dry-run (or "estimate") asks BigQuery for a free
		estimate instead of running. The estimate is an upper bound: it cannot
		see cluster pruning, so a lookup on a clustered table often estimates
		far above what it bills.

		Only SELECT statements are allowed. --limit caps the rows returned, not
		the bytes scanned: put LIMIT and WHERE clauses in the SQL to cut cost.
	`),
	TargetIntelQueryExample: heredoc.Doc(`
		$ vulncheck target-intel query --limit 10 --query "SELECT ip, port FROM anchorbreaker_prod.timeline WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 DAY) LIMIT 10"
		$ vulncheck ti query --from-file ./query.sql --all --json > rows.json
		$ vulncheck ti query --max-cost 10 --from-file big-join.sql
		$ vulncheck ti query --dry-run --from-file big-join.sql
	`),
	TargetIntelEstimateShort: "Estimate a query's cost without running it (free)",
	TargetIntelEstimateLong:  "Dry-runs the SQL and reports bytes scanned and estimated on-demand cost. Nothing is billed.",
	TargetIntelCvesShort:     "Hosts observed vulnerable to one or more CVEs (observations_by_cves_scored)",
	TargetIntelCvesLong: heredoc.Doc(`
		Calls the observations_by_cves_scored routine: every host seen in the
		lookback window whose fingerprint matches any of the given CVEs at or
		above the confidence tier. Each row carries matched_cve_id, the host's
		product, version, geolocation, ASN, EPSS and KEV fields.

		Confidence tiers: 40 and 30 are confirmed, 20 is the default, 10 adds
		product-level matches for versionless CPEs. Pass several CVEs in one
		call: the inputs are scanned once however many are given.

		Tiers 20 and above are served from a nightly match snapshot: the dry
		run estimates about 20 GiB ($0.12) and the bill is usually a third of
		that, because the snapshot is clustered on CVE. Tier 10, and any CVE
		whose NVD CPE mapping changed since the snapshot was built, are matched
		live and scan more. --max-cost applies exactly as for "query".
		Text mode shows a compact column set; --json returns every column.

		--group-by rolls the rows up to distinct hosts per country, asn,
		product or version (per matched CVE when several are given). --counts
		skips the routine and reads the nightly cve_host_counts table instead:
		hosts over the last 30 days split by tier, KEV and EPSS, and the top
		countries, for a fraction of a cent. --top reads the same table as a
		leaderboard: every CVE by exposed hosts, most first, optionally only
		KEV entries (--kev) or above an EPSS floor (--min-epss).
	`),
	TargetIntelCvesExample: heredoc.Doc(`
		$ vulncheck ti cves --cves CVE-2024-6387 --days 30
		$ vulncheck ti cves --cves CVE-2024-6387,CVE-2024-3400 --min-confidence 30 --json
		$ vulncheck ti cves --cves CVE-2024-3400 --all --json > hosts.json
		$ vulncheck ti cves --cves CVE-2024-6387 --dry-run
		$ vulncheck ti cves --cves CVE-2024-6387 --group-by country
		$ vulncheck ti cves --cves CVE-2024-6387,CVE-2024-3400 --counts
		$ vulncheck ti cves --top --kev --limit 10
	`),
	TargetIntelProductShort: "Hosts running a product or vendor (observations_by_product)",
	TargetIntelProductLong: heredoc.Doc(`
		Calls the observations_by_product routine: every host seen in the
		lookback window whose fingerprint matches the vendor and product
		patterns. Both are case-insensitive substring matches unless you pass
		an explicit LIKE pattern with %. The vendor pattern is also matched
		against the product name, so --vendor netscaler works when you do not
		know the vendor. At least one pattern is required.

		Rows carry the host's product, version, CPE, rule confidence,
		distro_packaged (likely or possibly, when the product ships as a
		distribution package), geolocation and ASN. A 30-day call dry-runs at
		about 63 GiB ($0.38) and bills what it estimates. --group-by rolls the
		rows up to distinct hosts per country, asn, product or version and
		reads fewer columns, about 36 GiB ($0.22). --max-cost applies exactly
		as for "query". Text mode shows a compact column set; --json returns
		every column.
	`),
	TargetIntelProductExample: heredoc.Doc(`
		$ vulncheck ti product --vendor citrix --product netscaler
		$ vulncheck ti product --product netscaler --group-by version
		$ vulncheck ti product --vendor fortinet --days 7 --group-by country --json
		$ vulncheck ti product --product "mini_httpd" --all --json > hosts.json
	`),
	TargetIntelHostShort: "What one host is running: listening ports, geolocation, current fingerprints and CVEs by confidence tier",
	TargetIntelHostLong: heredoc.Doc(`
		Looks one IPv4 address up in three point reads: host_profile for the
		ports and protocols seen listening in the current scan window, with
		geolocation and ASN; fingerprint_current for every product
		identified in the host's most recent scan of each port within the
		lookback window; and cpe_cve_matches for the CVEs those products'
		CPEs map to. All three are clustered on the host, so a lookup bills
		about 1 GiB (under a cent).

		Ports are those observed listening, bounded by what we probed: an
		absent port means not seen listening, never closed.

		CVEs are scored on the same tier scale as "cves", the highest per
		port and CVE: 40 for a rule-annotated CVE on a versioned,
		probe-confirmed fingerprint, 30 for any other rule annotation or a
		version match with no distro backport risk, 20 for a version match a
		distro may have patched, 10 for a versionless product match. 40 and
		30 are confirmed. Only ports fingerprinted within the lookback window
		are scored. --min-confidence (default 20) drops lower tiers. CPE
		matches come from the nightly cpe_cve_matches build, which also
		matches a product's CPE aliases, so a host can list a CVE that
		"cves" does not return for it.

		--json returns {query, found, profile, fingerprints, cves,
		cves_below_min_confidence, jobs}.

		A CIDR of /16 or longer returns an inventory instead: one row per
		host seen listening in the range, with its services and the distinct
		products identified within the lookback window, in address order.
		The range filter prunes on the host clustering, so a /16 bills well
		under 1 GiB. --limit caps the hosts returned; --json returns the
		"query" payload shape plus the echoed query.
	`),
	TargetIntelHostExample: heredoc.Doc(`
		$ vulncheck ti host 112.173.82.65
		$ vulncheck ti host 112.173.82.65 --days 90 --json
		$ vulncheck ti host 112.173.82.65 --min-confidence 30
		$ vulncheck ti host 81.82.248.0/24
		$ vulncheck ti host 81.82.0.0/16 --all --json > hosts.json
		$ vulncheck ti host 112.173.82.65 --dry-run
	`),
	TargetIntelServiceShort: "Distinct service configurations (HTTP responses, ...) matching a filter",
	TargetIntelServiceLong: heredoc.Doc(`
		Lists the distinct configurations a protocol's scans have seen, read
		from that protocol's snapshot table: one row per distinct response,
		so a list to narrow down from rather than a list of hosts. Each
		protocol is a subcommand; http is the first. A lookup of the hosts
		serving a configuration is coming.
	`),
	TargetIntelServiceHTTPShort: "Distinct HTTP responses matching a title, server, favicon or hash",
	TargetIntelServiceHTTPLong: heredoc.Doc(`
		Reads http_snapshot, one row per distinct HTTP response, for the
		configurations last seen within --days (default 30, at most 365) that
		match every filter given. At least one of --title, --server,
		--favicon, --body-hash or --hash is required; --status only narrows
		alongside one of them.

		--title and --server are case-insensitive substring matches unless
		you pass an explicit LIKE pattern with %. --favicon picks its column
		by shape: a decimal integer is the Shodan (mmh3) hash, 32 hex
		characters MD5, 64 hex characters SHA-256.

		The response body and headers are never read, which is what keeps
		this cheap: a 30-day search dry-runs at about 49 GiB ($0.30)
		whatever the filters, and a --hash lookup bills far less, since the
		table is clustered on it. --max-cost applies exactly as for "query".

		Rows come back newest last_seen first. --limit (default 100) is a
		LIMIT in the SQL, so BigQuery never sorts an unbounded set; total_rows
		is therefore the rows returned, not the rows matched, and truncated is
		always false. Text mode leaves out body_sha_256 and first_seen;
		--json returns every column plus table and the echoed query.
	`),
	TargetIntelServiceHTTPExample: heredoc.Doc(`
		$ vulncheck ti service http --title "fortigate"
		$ vulncheck ti service http --server "mini_httpd" --status 200 --days 7
		$ vulncheck ti service http --favicon -1132923558 --json
		$ vulncheck ti service http --title "Index of /%" --dry-run
	`),

	NvdShort:            "Query the NVD API 2.0 compatible endpoints (api /rest/json)",
	NvdCvesShort:        "Search CVEs (GET /rest/json/cves/2.0)",
	NvdCveHistoryShort:  "Search CVE change history (GET /rest/json/cvehistory/2.0)",
	NvdCpesShort:        "Search the CPE dictionary (GET /rest/json/cpes/2.0)",
	NvdCpeMatchShort:    "Search CPE match criteria (GET /rest/json/cpematch/2.0)",
	NvdSourceShort:      "List data sources (GET /rest/json/source/2.0)",
	NvdFound:            "%d of %d results",
	NvdNextCursor:       "Next page: --cursor %s",
	NvdFlagFullResponse: "Output the full NVD response, including totalResults and nextCursor",

	BackupShort: "Fetch or download a bulk archive",
	BackupLong: heredoc.Doc(`
		Fetch or download a bulk archive.

		  backup url|download <index>           v3, the index's native records
		  backup advisory url|download <feed>   v4, CVE 5.2 records, one per CVE
	`),
	BackupListShort:     "List indices that have a backup available",
	BackupListFull:      "Listing %d backups",
	BackupUrlShort:      "Get the temporary signed URL of the backup of an index",
	BackupDownloadShort: "Download the backup of an index",

	BackupDownloadInfo:     "Downloading backup of %s, created on %s",
	BackupDownloadProgress: "Downloading backup as %s",
	BackupDownloadComplete: "Backup downloaded successfully",

	BackupAdvisoryShort:         "Download a v4 advisory feed backup",
	BackupAdvisoryOverwrite:     "%s has no timestamp in its name; a repeat download replaces it in place",
	BackupAdvisoryListShort:     "List advisory feeds that have a backup available (GET /v4/backup)",
	BackupAdvisoryListFull:      "Listing %d advisory feed backups",
	BackupAdvisoryUrlShort:      "Get the temporary signed URL of an advisory feed backup (GET /v4/backup/{feed})",
	BackupAdvisoryDownloadShort: "Download an advisory feed backup (GET /v4/backup/{feed})",
	BackupAdvisoryDownloadInfo:  "Downloading advisory feed backup of %s",
	BackupAdvisoryErrorRequired: "feed name is required",
	BackupAdvisoryUnavailable:   "no backup is currently available for feed '%s'",

	CpeShort:               "Look up a specified cpe for any related CVEs",
	CpeExample:             "vulncheck cpe \"%s\"",
	CpeNoCves:              "No CVEs were found for cpe %s",
	CpeCvesFound:           "%d CVEs were found for cpe %s",
	CpeErrorSchemeRequired: "cpe scheme is required",

	PurlShort:               "Look up a specified PURL for any CVEs or vulnerabilities",
	PurlExample:             "vulncheck purl \"%s\"",
	PurlErrorSchemeRequired: "purl scheme is required",

	PurlNoVulns:    "No Vulnerabilities were found for purl %s",
	PurlVulnFound:  "1 Vulnerability were found for purl %s",
	PurlVulnsFound: "%d Vulnerabilities were found for purl %s",

	RuleShort:                 "Look up a specified rule for Initial Access Intelligence",
	RuleErrorRequired:         "rule name is required",
	RuleExample:               "vulncheck rule \"%s\" \nvulncheck rule \"%s\"",
	RuleErrorRuleNameRequired: "rule name is required",

	TagShort:                "List IP Intelligence Tags",
	TagExample:              "vulncheck tag \"%s\"",
	TagErrorTagNameRequired: "tag name is required",

	PdnsShort:                 "List IP Intelligence Protective DNS records",
	PdnsExample:               "vulncheck pdns \"%s\"",
	PdnsErrorListNameRequired: "list name is required",

	ScanShort:                   "Scan a directory for vulnerabilities",
	ScanExample:                 "vulncheck scan /path/to/directory",
	ScanSbomStart:               "Generating SBOM",
	ScanSbomLoad:                "Loading SBOM file %s",
	ScanSbomEnd:                 "SBOM created",
	ScanSbomLoaded:              "SBOM file loadded",
	ScanExtractPurlStart:        "Extracting PURLs",
	ScanExtractPurlEnd:          "%d PURLs extracted",
	ScanScanPurlStart:           "Scanning PURLs",
	ScanScanPurlStartOffline:    "[OFFLINE] Scanning PURLs",
	ScanScanPurlProgress:        "Scanning PURLs [%d/%d]",
	ScanScanPurlProgressOffline: "[OFFLINE] Scanning PURLs [%d/%d]",
	ScanScanPurlEnd:             "Scanning PURLs: %d vulns found in %d packages",
	ScanScanPurlEndPartial:      "Scanning PURLs: %d vulns found in %d of %d packages",
	ScanUnprocessed:             "%d of %d components could not be assessed and are not counted above:",
	ScanUnprocessedMore:         "  ...and %d more (see the scan output file for the full list)",
	ScanScanPurlEndOffline:      "[OFFLINE] Scanning PURLs: %d vulns found in %d packages",

	ScanScanCpeStartOffline:    "[OFFLINE] Scanning CPEs",
	ScanScanCpeProgressOffline: "[OFFLINE] Scanning CPEs [%d/%d]",
	ScanScanCpeEndOffline:      "[OFFLINE] Scanning CPEs: %d vulns found in %d",

	ScanExtractCpeStart: "Extracting CPEs",
	ScanExtractCpeEnd:   "%d CPEs extracted",

	ScanVulnMetaStart: "Fetching vulnerability metadata",
	ScanVulnMetaEnd:   "Vulnerability metadata fetched",

	ScanVulnOfflineMetaStart: "[OFFLINE] Fetching vulnerability metadata",
	ScanVulnOfflineMetaEnd:   "[OFFLINE] Vulnerability metadata fetched",

	ScanVulnOfflineMetaUnavailable: "CVSS scores, KEV status, and descriptions are unavailable because the vulncheck-nvd2 index is not cached. Run: vulncheck offline sync --add vulncheck-nvd2",

	ScanNoCvesFound:            "No vulnerabilities found in %d packages",
	ScanBenchmark:              "Scan completed in %s",
	ScanErrorDirectoryRequired: "Error: Directory is required",

	UpgradeShort: "Upgrade the vulncheck CLI to the latest version",
	UpgradeLong: heredoc.Doc(`
			Upgrade the vulncheck CLI to the latest version by downloading
			and installing the appropriate binary for your platform from GitHub releases.
		`),

	UpgradeLatestShort: "Upgrade to the latest version",
	UpgradeLatestLong:  "Upgrade to the latest version of the CLI.",

	UpgradeStatusShort: "Check upgrade status",
	UpgradeStatusLong:  "Check if a new version of the CLI is available.",

	ErrorUnauthorized: "Error: Unauthorized, Try authenticating with: vulncheck auth login",
	ErrorNoToken:      "No token found. Please run `vulncheck auth login` to authenticate or populate the environment variable `VULNCHECK_API_TOKEN`.",

	OfflineStatusShort: "Check the status of the offline database",
	OfflineStatusLong:  "Check the status of the offline database",
}

func Init() {
	C = En
	// TODO: after a 2nd language is added, detect the system language and set the lang variable accordingly
	// look at the LANG environment variable
	// bonus: missing keys of the 2nd language fallback to En
}
