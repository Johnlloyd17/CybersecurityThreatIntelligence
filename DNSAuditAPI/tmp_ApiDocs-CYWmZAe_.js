import{j as e,H as f,r as l}from"./index-CFKu6LhM.js";import{A as o,a as s,b as i,c as r}from"./accordion-Cbcdiayx.js";import{T as j,a as y,b as d,c as m}from"./tabs-CSAZcbvE.js";import{B as g}from"./Breadcrumbs-vmUX-SxX.js";const N=()=>e.jsxs("div",{className:"space-y-8",children:[e.jsxs("section",{className:"bg-white p-6 rounded-lg shadow-sm border border-gray-200 mb-8",children:[e.jsx("h2",{className:"text-2xl font-bold mb-4 text-blue-600",children:"Introduction to DNSAudit.io Scanner API"}),e.jsxs("div",{className:"space-y-6",children:[e.jsx("p",{className:"text-gray-700",children:"DNSAudit.io provides a high-performance DNS security scanner API that performs comprehensive security and misconfiguration checks on domain names. This documentation serves as a complete guide for implementing all security checks in the Go-based scanner microservice."}),e.jsxs("div",{className:"bg-blue-50 p-4 rounded-md border border-blue-200 mb-6",children:[e.jsx("h3",{className:"font-semibold text-lg mb-2",children:"Message to Go Implementation Developer"}),e.jsx("p",{className:"mb-2",children:"This documentation provides all the specifications needed to build the Go-based DNS scanner microservice. As you implement the API endpoints:"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-1",children:[e.jsx("li",{children:"Follow the detailed implementation instructions for each DNS check"}),e.jsxs("li",{children:["Implement all security checks using the ",e.jsx("code",{children:"miekg/dns"})," Go library"]}),e.jsx("li",{children:"Run all checks in parallel using goroutines for maximum performance"}),e.jsx("li",{children:"Implement tiered cache for optimized performance"}),e.jsxs("li",{children:["Create a protected admin interface at ",e.jsx("code",{children:"/stats"})," for monitoring API usage and performance"]}),e.jsx("li",{children:"Structure the Go implementation following clean architecture principles"})]}),e.jsx("p",{className:"mt-4",children:'The admin interface should display visualization of API usage metrics, performance stats, most active users, and system health. Protect this interface with user authentication. See the "Admin Interface Specifications" section below for details.'})]}),e.jsx("h3",{className:"text-xl font-semibold",children:"API Base URL"}),e.jsxs("p",{className:"mb-4",children:["The base URL for all API endpoints is: ",e.jsx("code",{children:"https://api.dnsaudit.io/v1"})]}),e.jsx("h3",{className:"text-xl font-semibold",children:"Authentication"}),e.jsx("p",{className:"mb-2",children:"All API requests require authentication using an API key:"}),e.jsxs("ul",{className:"list-disc pl-5 mb-4",children:[e.jsxs("li",{children:["Include your API key in the request header: ",e.jsx("code",{children:"X-API-Key: your_api_key"})]}),e.jsx("li",{children:"Rate limits are enforced on a per-key basis (30 requests per minute)"}),e.jsx("li",{children:"Contact support to increase your rate limit for enterprise usage"})]}),e.jsx("h3",{className:"text-xl font-semibold",children:"Response Format"}),e.jsx("p",{className:"mb-2",children:"All API responses follow a standard format:"}),e.jsx("pre",{className:"bg-gray-50 p-3 rounded text-sm overflow-auto mb-4",children:`{
  "status": "success", // or "error"
  "domain": "example.com",
  "scanDate": "2025-05-08T12:34:56Z",
  "scanId": "fae58a5f-1234-5678-9abc-def012345678",
  "scanScore": 85, // 0-100 score where 100 is perfect
  "scanSummary": {
    "critical": 0,  // Number of critical issues
    "warning": 2,   // Number of warning issues
    "passed": 24,   // Number of passed checks
    "info": 3       // Number of informational findings
  },
  "records": [...],  // Array of all DNS records found
  "issues": [...],   // Array of identified security issues
  "recommendations": [...] // Array of recommendations
}`})]})]}),e.jsxs("section",{className:"bg-white p-6 rounded-lg shadow-sm border border-gray-200 mb-8",children:[e.jsx("h2",{className:"text-2xl font-bold mb-4 text-blue-600",children:"API Endpoints"}),e.jsxs("div",{className:"space-y-6",children:[e.jsxs("div",{className:"mb-8",children:[e.jsx("h3",{className:"text-xl font-semibold text-blue-700",children:"Scan Domain"}),e.jsxs("p",{className:"mb-2",children:[e.jsx("span",{className:"font-bold",children:"POST"})," ",e.jsx("code",{children:"/scan"})]}),e.jsx("p",{className:"mb-2",children:"Performs a comprehensive DNS security scan on the specified domain."}),e.jsx("h4",{className:"font-medium mt-4 mb-2",children:"Request Parameters"}),e.jsx("div",{className:"overflow-x-auto",children:e.jsxs("table",{className:"min-w-full divide-y divide-gray-200",children:[e.jsx("thead",{className:"bg-gray-50",children:e.jsxs("tr",{children:[e.jsx("th",{className:"px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider",children:"Parameter"}),e.jsx("th",{className:"px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider",children:"Type"}),e.jsx("th",{className:"px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider",children:"Required"}),e.jsx("th",{className:"px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider",children:"Description"})]})}),e.jsxs("tbody",{className:"bg-white divide-y divide-gray-200",children:[e.jsxs("tr",{children:[e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm font-medium text-gray-900",children:"domain"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:"string"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:"Yes"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:'The domain name to scan (without protocol, e.g. "example.com")'})]}),e.jsxs("tr",{children:[e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm font-medium text-gray-900",children:"checkTypes"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:"array"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:"No"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:"Array of check types to run (default: all checks)"})]}),e.jsxs("tr",{children:[e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm font-medium text-gray-900",children:"includeRawRecords"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:"boolean"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:"No"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:"Whether to include raw DNS records in response (default: false)"})]})]})]})}),e.jsx("h4",{className:"font-medium mt-4 mb-2",children:"Example Request"}),e.jsx("pre",{className:"bg-gray-50 p-3 rounded text-sm overflow-auto",children:`// Scan example.com with all security checks
POST /scan HTTP/1.1
Host: api.dnsaudit.io
X-API-Key: your_api_key
Content-Type: application/json

{
  "domain": "example.com"
}`}),e.jsx("h4",{className:"font-medium mt-4 mb-2",children:"Example Response"}),e.jsx("pre",{className:"bg-gray-50 p-3 rounded text-sm overflow-auto",children:`{
  "status": "success",
  "domain": "example.com",
  "scanDate": "2025-05-08T12:34:56Z",
  "scanId": "fae58a5f-1234-5678-9abc-def012345678",
  "scanScore": 85,
  "scanSummary": {
    "critical": 0,
    "warning": 2,
    "passed": 24,
    "info": 3
  },
  "records": [
    {
      "type": "A",
      "name": "example.com",
      "value": "93.184.216.34",
      "ttl": 86400
    },
    // More records...
  ],
  "issues": [
    {
      "checkType": "spf",
      "severity": "warning",
      "title": "Weak SPF policy",
      "description": "SPF policy uses ~all instead of recommended -all",
      "recommendation": "Change SPF policy from ~all to -all for stronger protection"
    },
    // More issues...
  ],
  "recommendations": [
    {
      "title": "Implement DNSSEC",
      "description": "DNSSEC is not implemented for this domain. Consider implementing DNSSEC to ensure DNS records cannot be tampered with."
    },
    // More recommendations...
  ]
}`})]}),e.jsxs("div",{className:"mb-8",children:[e.jsx("h3",{className:"text-xl font-semibold text-blue-700",children:"Get Scan Status"}),e.jsxs("p",{className:"mb-2",children:[e.jsx("span",{className:"font-bold",children:"GET"})," ",e.jsxs("code",{children:["/scan/","{scanId}"]})]}),e.jsx("p",{className:"mb-2",children:"Retrieves the status or results of a previously initiated scan."}),e.jsx("h4",{className:"font-medium mt-4 mb-2",children:"Path Parameters"}),e.jsx("div",{className:"overflow-x-auto",children:e.jsxs("table",{className:"min-w-full divide-y divide-gray-200",children:[e.jsx("thead",{className:"bg-gray-50",children:e.jsxs("tr",{children:[e.jsx("th",{className:"px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider",children:"Parameter"}),e.jsx("th",{className:"px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider",children:"Type"}),e.jsx("th",{className:"px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider",children:"Required"}),e.jsx("th",{className:"px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider",children:"Description"})]})}),e.jsx("tbody",{className:"bg-white divide-y divide-gray-200",children:e.jsxs("tr",{children:[e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm font-medium text-gray-900",children:"scanId"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:"string"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:"Yes"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:"The unique identifier for the scan"})]})})]})}),e.jsx("h4",{className:"font-medium mt-4 mb-2",children:"Example Request"}),e.jsx("pre",{className:"bg-gray-50 p-3 rounded text-sm overflow-auto",children:`GET /scan/fae58a5f-1234-5678-9abc-def012345678 HTTP/1.1
Host: api.dnsaudit.io
X-API-Key: your_api_key`})]}),e.jsxs("div",{className:"mb-8",children:[e.jsx("h3",{className:"text-xl font-semibold text-blue-700",children:"Get Domain History"}),e.jsxs("p",{className:"mb-2",children:[e.jsx("span",{className:"font-bold",children:"GET"})," ",e.jsxs("code",{children:["/domain/","{domain}","/history"]})]}),e.jsx("p",{className:"mb-2",children:"Retrieves the scan history for a specific domain."}),e.jsx("h4",{className:"font-medium mt-4 mb-2",children:"Path Parameters"}),e.jsx("div",{className:"overflow-x-auto",children:e.jsxs("table",{className:"min-w-full divide-y divide-gray-200",children:[e.jsx("thead",{className:"bg-gray-50",children:e.jsxs("tr",{children:[e.jsx("th",{className:"px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider",children:"Parameter"}),e.jsx("th",{className:"px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider",children:"Type"}),e.jsx("th",{className:"px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider",children:"Required"}),e.jsx("th",{className:"px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider",children:"Description"})]})}),e.jsx("tbody",{className:"bg-white divide-y divide-gray-200",children:e.jsxs("tr",{children:[e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm font-medium text-gray-900",children:"domain"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:"string"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:"Yes"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:"The domain name to get history for"})]})})]})}),e.jsx("h4",{className:"font-medium mt-4 mb-2",children:"Query Parameters"}),e.jsx("div",{className:"overflow-x-auto",children:e.jsxs("table",{className:"min-w-full divide-y divide-gray-200",children:[e.jsx("thead",{className:"bg-gray-50",children:e.jsxs("tr",{children:[e.jsx("th",{className:"px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider",children:"Parameter"}),e.jsx("th",{className:"px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider",children:"Type"}),e.jsx("th",{className:"px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider",children:"Required"}),e.jsx("th",{className:"px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider",children:"Description"})]})}),e.jsxs("tbody",{className:"bg-white divide-y divide-gray-200",children:[e.jsxs("tr",{children:[e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm font-medium text-gray-900",children:"limit"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:"integer"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:"No"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:"Maximum number of results to return (default: 10, max: 100)"})]}),e.jsxs("tr",{children:[e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm font-medium text-gray-900",children:"from"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:"string"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:"No"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:'Start date in ISO 8601 format (e.g., "2025-01-01T00:00:00Z")'})]}),e.jsxs("tr",{children:[e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm font-medium text-gray-900",children:"to"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:"string"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:"No"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:'End date in ISO 8601 format (e.g., "2025-12-31T23:59:59Z")'})]})]})]})})]}),e.jsxs("div",{className:"mb-8",children:[e.jsx("h3",{className:"text-xl font-semibold text-blue-700",children:"Compare Domain Scans"}),e.jsxs("p",{className:"mb-2",children:[e.jsx("span",{className:"font-bold",children:"GET"})," ",e.jsx("code",{children:"/scan/compare"})]}),e.jsx("p",{className:"mb-2",children:"Compares two scan results for a domain to identify changes."}),e.jsx("h4",{className:"font-medium mt-4 mb-2",children:"Query Parameters"}),e.jsx("div",{className:"overflow-x-auto",children:e.jsxs("table",{className:"min-w-full divide-y divide-gray-200",children:[e.jsx("thead",{className:"bg-gray-50",children:e.jsxs("tr",{children:[e.jsx("th",{className:"px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider",children:"Parameter"}),e.jsx("th",{className:"px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider",children:"Type"}),e.jsx("th",{className:"px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider",children:"Required"}),e.jsx("th",{className:"px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider",children:"Description"})]})}),e.jsxs("tbody",{className:"bg-white divide-y divide-gray-200",children:[e.jsxs("tr",{children:[e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm font-medium text-gray-900",children:"scanId1"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:"string"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:"Yes"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:"ID of the first scan to compare"})]}),e.jsxs("tr",{children:[e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm font-medium text-gray-900",children:"scanId2"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:"string"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:"Yes"}),e.jsx("td",{className:"px-4 py-2 whitespace-nowrap text-sm text-gray-500",children:"ID of the second scan to compare"})]})]})]})}),e.jsx("h4",{className:"font-medium mt-4 mb-2",children:"Example Request"}),e.jsx("pre",{className:"bg-gray-50 p-3 rounded text-sm overflow-auto",children:`GET /scan/compare?scanId1=fae58a5f-1234&scanId2=ebd12345-6789 HTTP/1.1
Host: api.dnsaudit.io
X-API-Key: your_api_key`})]})]})]}),e.jsxs("section",{className:"bg-white p-6 rounded-lg shadow-sm border border-gray-200 mb-8",children:[e.jsx("h2",{className:"text-2xl font-bold mb-4 text-blue-600",children:"Data Models"}),e.jsxs("div",{className:"space-y-6",children:[e.jsxs("div",{className:"mb-6",children:[e.jsx("h3",{className:"text-xl font-semibold text-blue-700",children:"DNS Record"}),e.jsx("p",{className:"mb-2",children:"Represents a DNS record returned from a scan."}),e.jsx("pre",{className:"bg-gray-50 p-3 rounded text-sm overflow-auto",children:'type DnsRecord struct {\n  RecordType    string      `json:"type"`\n  Name          string      `json:"name"`\n  Value         string      `json:"value"`\n  TTL           int         `json:"ttl"`\n  Priority      int         `json:"priority,omitempty"`   // For MX records\n  RawRecord     interface{} `json:"rawRecord,omitempty"`  // Original parsed record\n  Status        string      `json:"status,omitempty"`     // secure, warning, critical, info\n  StatusMessage string      `json:"statusMessage,omitempty"`\n}'})]}),e.jsxs("div",{className:"mb-6",children:[e.jsx("h3",{className:"text-xl font-semibold text-blue-700",children:"Issue"}),e.jsx("p",{className:"mb-2",children:"Represents a security issue identified during a scan."}),e.jsx("pre",{className:"bg-gray-50 p-3 rounded text-sm overflow-auto",children:'type Issue struct {\n  CheckType     string   `json:"checkType"`\n  Severity      string   `json:"severity"`  // critical, warning, info\n  Title         string   `json:"title"`\n  Description   string   `json:"description"`\n  Recommendation string  `json:"recommendation"`\n  AffectedRecords []string `json:"affectedRecords,omitempty"`\n  References    []string `json:"references,omitempty"`  // Links to documentation\n}'})]}),e.jsxs("div",{className:"mb-6",children:[e.jsx("h3",{className:"text-xl font-semibold text-blue-700",children:"Recommendation"}),e.jsx("p",{className:"mb-2",children:"Represents a security recommendation for the domain."}),e.jsx("pre",{className:"bg-gray-50 p-3 rounded text-sm overflow-auto",children:'type Recommendation struct {\n  Title         string   `json:"title"`\n  Description   string   `json:"description"`\n  Priority      string   `json:"priority"`  // high, medium, low\n  Implementation string  `json:"implementation"`\n  References    []string `json:"references,omitempty"`\n}'})]}),e.jsxs("div",{className:"mb-6",children:[e.jsx("h3",{className:"text-xl font-semibold text-blue-700",children:"Domain History"}),e.jsx("p",{className:"mb-2",children:"Represents the scan history for a domain."}),e.jsx("pre",{className:"bg-gray-50 p-3 rounded text-sm overflow-auto",children:'type DomainHistory struct {\n  Domain        string     `json:"domain"`\n  Scans         []ScanInfo `json:"scans"`\n  TotalScans    int        `json:"totalScans"`\n  FirstScanDate string     `json:"firstScanDate"`\n  LastScanDate  string     `json:"lastScanDate"`\n}\n\ntype ScanInfo struct {\n  ScanId        string     `json:"scanId"`\n  ScanDate      string     `json:"scanDate"`\n  ScanScore     int        `json:"scanScore"`\n  ScanSummary   ScanSummary `json:"scanSummary"`\n}'})]})]})]}),e.jsxs("section",{className:"bg-white p-6 rounded-lg shadow-sm border border-gray-200 mb-8",children:[e.jsx("h2",{className:"text-2xl font-bold mb-4 text-blue-600",children:"Scanner Core Interface"}),e.jsxs("div",{className:"space-y-6",children:[e.jsx("p",{className:"mb-2",children:"The core scanner interface defines the structure for all DNS checks in the Go implementation."}),e.jsx("pre",{className:"bg-gray-50 p-3 rounded text-sm overflow-auto",children:`// DNSChecker interface should be implemented by all DNS security checks
type DNSChecker interface {
  // Name returns the name of the check (used in logs and reports)
  Name() string
  
  // Type returns the check type identifier
  Type() string
  
  // Run performs the actual check against the given domain
  Run(ctx context.Context, domain string, nameservers []string) ([]DnsRecord, []Issue, error)
  
  // Priority returns the execution priority of this check
  Priority() int
}

// Scanner orchestrates the execution of all DNS checks
type Scanner struct {
  checkers     []DNSChecker
  cache        Cache
  resolver     Resolver
  logger       Logger
  resultStore  ResultStore
}

// ScanDomain runs all security checks for a domain
func (s *Scanner) ScanDomain(ctx context.Context, domain string, opts ScanOptions) (*ScanResult, error) {
  // Implementation details...
}

// Resolver interface handles DNS resolution
type Resolver interface {
  Resolve(ctx context.Context, domain string, recordType uint16, nameserver string) ([]dns.RR, error)
  GetNameservers(ctx context.Context, domain string) ([]string, error)
}

// Cache interface for DNS caching
type Cache interface {
  Get(key string) (interface{}, bool)
  Set(key string, value interface{}, ttl time.Duration)
  Delete(key string)
  Flush()
  Stats() CacheStats
}

// ResultStore interface for saving scan results
type ResultStore interface {
  SaveScanResult(result *ScanResult) error
  GetScanResult(scanId string) (*ScanResult, error)
  GetDomainHistory(domain string, limit int, from, to time.Time) (*DomainHistory, error)
}

// API setup in main.go:
func main() {
  // Initialize dependencies
  cache := cache.NewTieredCache()
  resolver := dns.NewResolver()
  logger := log.NewLogger()
  resultStore := storage.NewResultStore()
  
  // Create scanner with all checks
  scanner := scanner.NewScanner(
    scanner.WithCache(cache),
    scanner.WithResolver(resolver),
    scanner.WithLogger(logger),
    scanner.WithResultStore(resultStore),
    scanner.WithCheckers(
      // Standard record checks
      checks.NewARecordChecker(),
      checks.NewAAAARecordChecker(),
      // ... Other checkers
    ),
  )
  
  // Setup API routes
  router := mux.NewRouter()
  
  // API endpoints
  router.HandleFunc("/v1/scan", api.HandleScanDomain(scanner)).Methods("POST")
  router.HandleFunc("/v1/scan/{"scanId"}", api.HandleGetScanStatus(resultStore)).Methods("GET")
  router.HandleFunc("/v1/domain/{"domain"}/history", api.HandleGetDomainHistory(resultStore)).Methods("GET")
  router.HandleFunc("/v1/scan/compare", api.HandleCompareDomainScans(resultStore)).Methods("GET")
  
  // Admin interface routes (protected by authentication)
  admin := router.PathPrefix("/stats").Subrouter()
  admin.Use(middleware.AuthMiddleware)
  admin.HandleFunc("/", adminHandlers.Dashboard).Methods("GET")
  admin.HandleFunc("/users", adminHandlers.UserStats).Methods("GET")
  admin.HandleFunc("/performance", adminHandlers.PerformanceStats).Methods("GET")
  
  // Start server
  log.Fatal(http.ListenAndServe(":8080", router))
}`})]})]}),e.jsxs("section",{className:"bg-white p-6 rounded-lg shadow-sm border border-gray-200 mb-8",children:[e.jsx("h2",{className:"text-2xl font-bold mb-4 text-blue-600",children:"Cache Implementation"}),e.jsxs("div",{className:"space-y-6",children:[e.jsx("p",{className:"mb-4",children:"The tiered caching system optimizes performance by using multiple cache levels."}),e.jsx("pre",{className:"bg-gray-50 p-3 rounded text-sm overflow-auto",children:`// TieredCache combines in-memory and Redis caches for optimal performance
type TieredCache struct {
  memoryCache  *MemoryCache
  redisCache   *RedisCache
  logger       Logger
}

// NewTieredCache creates a new tiered cache system
func NewTieredCache(opts ...CacheOption) *TieredCache {
  tc := &TieredCache{
    memoryCache: NewMemoryCache(256*1024*1024), // 256MB default
    redisCache:  NewRedisCache(),
    logger:      log.DefaultLogger,
  }
  
  for _, opt := range opts {
    opt(tc)
  }
  
  return tc
}

// Get retrieves a value from cache, trying memory first then Redis
func (tc *TieredCache) Get(key string) (interface{}, bool) {
  // Try memory cache first (fastest)
  if value, found := tc.memoryCache.Get(key); found {
    tc.logger.Debug("Memory cache hit", "key", key)
    return value, true
  }
  
  // Try Redis cache second
  if tc.redisCache != nil {
    if value, found := tc.redisCache.Get(key); found {
      // Populate memory cache for next time
      tc.memoryCache.Set(key, value, defaultTTL)
      tc.logger.Debug("Redis cache hit", "key", key)
      return value, true
    }
  }
  
  return nil, false
}

// Set stores a value in both memory and Redis caches
func (tc *TieredCache) Set(key string, value interface{}, ttl time.Duration) {
  // Always set in memory cache
  tc.memoryCache.Set(key, value, ttl)
  
  // Set in Redis if available
  if tc.redisCache != nil {
    tc.redisCache.Set(key, value, ttl)
  }
}

// Delete removes a value from all cache levels
func (tc *TieredCache) Delete(key string) {
  tc.memoryCache.Delete(key)
  if tc.redisCache != nil {
    tc.redisCache.Delete(key)
  }
}

// MemoryCache implements an in-memory LRU cache with TTL expiration
type MemoryCache struct {
  cache       map[string]cacheEntry
  maxSize     int64
  currentSize int64
  mu          sync.RWMutex
  stats       CacheStats
}

type cacheEntry struct {
  value      interface{}
  expiration time.Time
  size       int64
  lastAccess time.Time
}

// NewMemoryCache creates a new memory cache with specified max size in bytes
func NewMemoryCache(maxSizeBytes int64) *MemoryCache {
  return &MemoryCache{
    cache:   make(map[string]cacheEntry),
    maxSize: maxSizeBytes,
    stats:   CacheStats{},
  }
}

// Implementation details for Get, Set, Delete, cleanup, etc.

// RedisCache implements a Redis-backed cache
type RedisCache struct {
  client *redis.Client
  stats  CacheStats
}

// NewRedisCache creates a new Redis cache
func NewRedisCache(opts ...RedisOption) *RedisCache {
  rc := &RedisCache{
    client: redis.NewClient(&redis.Options{
      Addr:     "localhost:6379",
      Password: "",
      DB:       0,
    }),
    stats: CacheStats{},
  }
  
  for _, opt := range opts {
    opt(rc)
  }
  
  return rc
}

// Implementation details for Get, Set, Delete, etc.`})]})]}),e.jsxs("section",{className:"bg-white p-6 rounded-lg shadow-sm border border-gray-200 mb-8",children:[e.jsx("h2",{className:"text-2xl font-bold mb-4 text-blue-600",children:"Admin Interface Specifications"}),e.jsxs("div",{className:"space-y-6",children:[e.jsxs("p",{className:"mb-4",children:["The admin interface at ",e.jsx("code",{children:"/stats"})," provides performance monitoring, usage statistics, and system health information. This interface should be implemented as part of the Go API server."]}),e.jsx("h3",{className:"text-xl font-semibold text-blue-700",children:"Authentication"}),e.jsx("p",{className:"mb-2",children:"Protect the admin interface using HTTP Basic Authentication:"}),e.jsx("pre",{className:"bg-gray-50 p-3 rounded text-sm overflow-auto",children:`// Authentication middleware
func AuthMiddleware(next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    user, pass, ok := r.BasicAuth()
    
    // Check credentials against environment variables or secured database
    if !ok || user != os.Getenv("ADMIN_USER") || pass != os.Getenv("ADMIN_PASSWORD") {
      w.Header().Set("WWW-Authenticate", \`Basic realm="Admin Access"\`)
      http.Error(w, "Unauthorized", http.StatusUnauthorized)
      return
    }
    
    next.ServeHTTP(w, r)
  })
}`}),e.jsx("h3",{className:"text-xl font-semibold text-blue-700",children:"Dashboard Components"}),e.jsx("p",{className:"mb-2",children:"The admin dashboard should include the following components:"}),e.jsxs("ol",{className:"list-decimal pl-5 space-y-3",children:[e.jsxs("li",{children:[e.jsx("span",{className:"font-medium",children:"System Overview"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1 mb-2",children:[e.jsx("li",{children:"Current server load (CPU, memory, network)"}),e.jsx("li",{children:"Request rate (requests per minute)"}),e.jsx("li",{children:"Average response time"}),e.jsx("li",{children:"Error rate"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-medium",children:"API Usage Metrics"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1 mb-2",children:[e.jsx("li",{children:"Total scans performed"}),e.jsx("li",{children:"Scans per day (with time-series chart)"}),e.jsx("li",{children:"Most frequently scanned domains"}),e.jsx("li",{children:"Endpoint usage distribution"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-medium",children:"Cache Performance"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1 mb-2",children:[e.jsx("li",{children:"Cache hit ratio"}),e.jsx("li",{children:"Memory cache size"}),e.jsx("li",{children:"Redis cache size"}),e.jsx("li",{children:"Most frequently cached items"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-medium",children:"User Analytics"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1 mb-2",children:[e.jsx("li",{children:"Top users by request volume"}),e.jsx("li",{children:"API key usage statistics"}),e.jsx("li",{children:"Rate limit violations"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-medium",children:"Error Monitoring"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1 mb-2",children:[e.jsx("li",{children:"Recent errors with details"}),e.jsx("li",{children:"Error distribution by type"}),e.jsx("li",{children:"Error rate trends"})]})]})]}),e.jsx("h3",{className:"text-xl font-semibold text-blue-700",children:"User Interface"}),e.jsx("p",{className:"mb-2",children:"Create a simple but effective web UI using:"}),e.jsxs("ul",{className:"list-disc pl-5 mb-4",children:[e.jsx("li",{children:"Basic HTML/CSS with a responsive layout"}),e.jsx("li",{children:"Chart.js for data visualization"}),e.jsx("li",{children:"Minimal JavaScript for dynamic updates"}),e.jsx("li",{children:"WebSocket for real-time updates (optional)"})]}),e.jsx("p",{className:"mb-2",children:"Provide both graphical visualizations and tabular data for all metrics."})]})]})]}),b=()=>e.jsxs("div",{children:[e.jsxs(f,{children:[e.jsx("title",{children:"DNS Security Checks Specifications | DNSAudit.io"}),e.jsx("meta",{name:"description",content:"Complete specifications for DNS security checks including standard records, email security, and advanced security validations."}),e.jsx("meta",{name:"keywords",content:"DNS security checks, DNS specifications, DNS validation, DNS scanner API"}),e.jsx("meta",{property:"og:title",content:"DNS Security Checks Specifications"}),e.jsx("meta",{property:"og:description",content:"Comprehensive technical documentation for DNS security check implementations and specifications."}),e.jsx("meta",{property:"og:type",content:"article"}),e.jsx("link",{rel:"canonical",href:"https://dnsaudit.io/docs/dns-checks-specifications"})]}),e.jsxs("div",{className:"min-h-screen bg-white",children:[e.jsx("div",{className:"bg-gray-50",children:e.jsx("div",{className:"max-w-4xl mx-auto px-4 py-6",children:e.jsx(g,{items:[{label:"Home",href:"/"},{label:"Documentation",href:"/docs"},{label:"DNS Security Checks",href:""}]})})}),e.jsxs("div",{className:"max-w-4xl mx-auto px-4 py-8",children:[e.jsx("h2",{className:"text-2xl font-bold mb-8 text-blue-600",children:"DNS Security Checks Specifications"}),e.jsxs("div",{className:"mb-8",children:[e.jsx("h3",{className:"text-lg font-semibold mb-4",children:"Why DNS Security Matters"}),e.jsx("p",{className:"text-gray-700 mb-4",children:"DNS (Domain Name System) is a critical internet infrastructure component that translates human-readable domain names into machine-readable IP addresses. However, DNS was designed in the 1980s with minimal security considerations, creating numerous vulnerabilities that malicious actors can exploit."}),e.jsx("p",{className:"text-gray-700 mb-4",children:"Proper DNS security is essential because:"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-2 text-gray-700 mb-4",children:[e.jsxs("li",{children:[e.jsx("strong",{children:"Data Integrity:"})," Unsecured DNS can be tampered with, redirecting users to malicious sites."]}),e.jsxs("li",{children:[e.jsx("strong",{children:"Information Protection:"})," DNS queries can leak sensitive information about your network and activities."]}),e.jsxs("li",{children:[e.jsx("strong",{children:"Service Availability:"})," DNS is a common target for denial-of-service attacks."]}),e.jsxs("li",{children:[e.jsx("strong",{children:"Email Security:"})," DNS records like SPF, DKIM, and DMARC are essential for preventing email spoofing and phishing."]}),e.jsxs("li",{children:[e.jsx("strong",{children:"Certificate Validation:"})," DNS security measures like CAA records help ensure proper certificate issuance."]})]}),e.jsx("p",{className:"text-gray-700",children:"Our comprehensive suite of DNS security checks examines all these aspects to identify vulnerabilities and misconfigurations before they can be exploited."})]}),e.jsxs(j,{defaultValue:"standard",children:[e.jsxs(y,{className:"grid w-full grid-cols-3",children:[e.jsx(d,{value:"standard",children:"Standard Records"}),e.jsx(d,{value:"email",children:"Email Security"}),e.jsx(d,{value:"advanced",children:"Advanced Security"})]}),e.jsx(m,{value:"standard",children:e.jsxs(o,{type:"single",collapsible:!0,className:"w-full",children:[e.jsxs(s,{value:"a-records",children:[e.jsx(i,{className:"text-left",children:"A Records"}),e.jsx(r,{children:e.jsxs("div",{className:"space-y-4",children:[e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Description"}),e.jsx("p",{children:"A records map a domain to IPv4 addresses. This check verifies that appropriate A records exist and are properly configured."})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Implementation Details"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-1",children:[e.jsx("li",{children:"Uses DNS lookups to retrieve all A records for the domain"}),e.jsx("li",{children:"Checks for presence of at least one valid A record"}),e.jsx("li",{children:"Verifies record TTL values are appropriate (not too short or too long)"}),e.jsx("li",{children:"Validates that IPs aren't pointing to known malicious address ranges"})]})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Security Implications"}),e.jsx("p",{children:"Misconfigured A records can lead to service disruptions or, in worst cases, redirect users to malicious servers if DNS records are tampered with."})]}),e.jsxs("div",{className:"bg-gray-50 p-3 rounded border border-gray-200",children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"API Response Example"}),e.jsx("pre",{className:"text-xs overflow-x-auto",children:`{
  "host": "example.com",
  "type": "A",
  "value": "93.184.216.34",
  "ttl": 3600,
  "status": "secure"
}`})]})]})})]}),e.jsxs(s,{value:"aaaa-records",children:[e.jsx(i,{className:"text-left",children:"AAAA Records"}),e.jsx(r,{children:e.jsxs("div",{className:"space-y-4",children:[e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Description"}),e.jsx("p",{children:"AAAA records map a domain to IPv6 addresses. This check verifies that appropriate AAAA records exist if IPv6 connectivity is offered."})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Implementation Details"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-1",children:[e.jsx("li",{children:"Uses DNS lookups to retrieve all AAAA records for the domain"}),e.jsx("li",{children:"Checks if IPv6 connectivity is properly configured"}),e.jsx("li",{children:"Not having AAAA records is considered informational rather than an issue"}),e.jsx("li",{children:"Validates that IPv6 addresses aren't pointing to known problematic ranges"})]})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Security Implications"}),e.jsx("p",{children:"While not having IPv6 support isn't a security vulnerability by itself, inconsistent or misconfigured AAAA records can lead to connectivity issues or IPv6-specific attack vectors."})]}),e.jsxs("div",{className:"bg-gray-50 p-3 rounded border border-gray-200",children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"API Response Example"}),e.jsx("pre",{className:"text-xs overflow-x-auto",children:`{
  "host": "example.com",
  "type": "AAAA",
  "value": "2606:2800:220:1:248:1893:25c8:1946",
  "ttl": 3600,
  "status": "secure"
}`})]})]})})]}),e.jsxs(s,{value:"mx-records",children:[e.jsx(i,{className:"text-left",children:"MX Records"}),e.jsx(r,{children:e.jsxs("div",{className:"space-y-4",children:[e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Description"}),e.jsx("p",{children:"MX records specify the mail servers responsible for accepting email for a domain. This check verifies proper mail server configuration."})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Implementation Details"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-1",children:[e.jsx("li",{children:"Retrieves all MX records for the domain"}),e.jsx("li",{children:"Verifies that multiple MX records exist for redundancy"}),e.jsx("li",{children:"Checks that MX records have appropriate priority values"}),e.jsx("li",{children:"Validates that mail servers have valid A/AAAA records"}),e.jsx("li",{children:"Attempts to detect if mail servers support secure email transport (STARTTLS)"})]})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Security Implications"}),e.jsx("p",{children:"Properly configured MX records are essential for reliable mail delivery. Improperly configured MX records can lead to mail delivery failures or potential mail server exploits."})]}),e.jsxs("div",{className:"bg-gray-50 p-3 rounded border border-gray-200",children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"API Response Example"}),e.jsx("pre",{className:"text-xs overflow-x-auto",children:`{
  "host": "example.com",
  "type": "MX",
  "value": "10 mail.example.com",
  "ttl": 3600,
  "status": "warning",
  "issues": ["Single MX record without backup"]
}`})]})]})})]}),e.jsxs(s,{value:"ns-records",children:[e.jsx(i,{className:"text-left",children:"NS Records"}),e.jsx(r,{children:e.jsxs("div",{className:"space-y-4",children:[e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Description"}),e.jsx("p",{children:"NS records delegate a DNS zone to a set of authoritative name servers. This check verifies proper nameserver configuration and redundancy."})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Implementation Details"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-1",children:[e.jsx("li",{children:"Retrieves all NS records for the domain"}),e.jsx("li",{children:"Verifies a minimum of two nameservers for redundancy"}),e.jsx("li",{children:"Checks that nameservers are responsive"}),e.jsx("li",{children:"Validates that nameservers are located on different networks"}),e.jsx("li",{children:"Examines nameserver software for known vulnerabilities"})]})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Security Implications"}),e.jsx("p",{children:"Nameservers are critical infrastructure for a domain. Insufficient redundancy or vulnerable nameserver software can lead to domain unavailability or hijacking."})]}),e.jsxs("div",{className:"bg-gray-50 p-3 rounded border border-gray-200",children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"API Response Example"}),e.jsx("pre",{className:"text-xs overflow-x-auto",children:`{
  "host": "example.com",
  "type": "NS",
  "value": "ns1.example.com",
  "status": "warning",
  "issues": ["Only one nameserver detected"]
}`})]})]})})]}),e.jsxs(s,{value:"txt-records",children:[e.jsx(i,{className:"text-left",children:"TXT Records"}),e.jsx(r,{children:e.jsxs("div",{className:"space-y-4",children:[e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Description"}),e.jsx("p",{children:"TXT records store text information in the DNS. This check examines TXT records for security-related information and potential data leakage."})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Implementation Details"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-1",children:[e.jsx("li",{children:"Retrieves all TXT records for the domain"}),e.jsx("li",{children:"Analyzes records for sensitive information disclosure"}),e.jsx("li",{children:"Identifies security-related TXT records such as SPF, DKIM, verification tokens"}),e.jsx("li",{children:"Checks for well-formed record syntax"}),e.jsx("li",{children:"Assesses text length and structure for potential vulnerabilities"})]})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Security Implications"}),e.jsx("p",{children:"While TXT records serve many legitimate purposes, they can unintentionally leak sensitive information about internal systems or configurations. They also host critical email security records."})]}),e.jsxs("div",{className:"bg-gray-50 p-3 rounded border border-gray-200",children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"API Response Example"}),e.jsx("pre",{className:"text-xs overflow-x-auto",children:`{
  "host": "example.com",
  "type": "TXT",
  "value": "v=spf1 include:_spf.example.com ~all",
  "ttl": 3600,
  "status": "secure"
}`})]})]})})]}),e.jsxs(s,{value:"cname-records",children:[e.jsx(i,{className:"text-left",children:"CNAME Records"}),e.jsx(r,{children:e.jsxs("div",{className:"space-y-4",children:[e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Description"}),e.jsx("p",{children:"CNAME records create an alias from one domain to another. This check verifies proper CNAME configuration and identifies potential security issues like dangling records."})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Implementation Details"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-1",children:[e.jsx("li",{children:"Retrieves all CNAME records for the domain and subdomains"}),e.jsx("li",{children:"Verifies that CNAMEs resolve to valid destinations"}),e.jsx("li",{children:"Checks for dangling CNAME records (pointing to non-existent destinations)"}),e.jsx("li",{children:"Validates that there are no CNAME loops or chains that are too long"}),e.jsx("li",{children:"Ensures no CNAME exists at the apex/root domain (which is invalid)"})]})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Security Implications"}),e.jsx("p",{children:"Dangling CNAME records can be exploited for subdomain takeover attacks. Improper CNAME configurations can also lead to service disruptions or unexpected behavior."})]}),e.jsxs("div",{className:"bg-gray-50 p-3 rounded border border-gray-200",children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"API Response Example"}),e.jsx("pre",{className:"text-xs overflow-x-auto",children:`{
  "host": "www.example.com",
  "type": "CNAME",
  "value": "example.com",
  "ttl": 3600,
  "status": "secure"
}`})]})]})})]})]})}),e.jsx(m,{value:"email",children:e.jsxs(o,{type:"single",collapsible:!0,className:"w-full",children:[e.jsxs(s,{value:"spf-records",children:[e.jsx(i,{className:"text-left",children:"SPF Records"}),e.jsx(r,{children:e.jsxs("div",{className:"space-y-4",children:[e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Description"}),e.jsx("p",{children:"Sender Policy Framework (SPF) records specify which mail servers are authorized to send email on behalf of a domain. This check verifies proper SPF implementation."})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Implementation Details"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-1",children:[e.jsx("li",{children:"Looks for SPF records in TXT records (format: v=spf1...)"}),e.jsx("li",{children:"Verifies there is exactly one SPF record (multiple records cause issues)"}),e.jsx("li",{children:"Checks SPF syntax for validity"}),e.jsx("li",{children:"Evaluates SPF policy strength (~all vs -all)"}),e.jsx("li",{children:"Analyzes SPF record for excessive DNS lookups (max 10 allowed)"}),e.jsx("li",{children:"Checks for deprecated SPF record types"})]})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Security Implications"}),e.jsx("p",{children:"Without proper SPF records, attackers can more easily spoof emails from your domain, leading to successful phishing attacks. Weak SPF policies (using ~all instead of -all) provide less protection against spoofing."})]}),e.jsxs("div",{className:"bg-gray-50 p-3 rounded border border-gray-200",children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"API Response Example"}),e.jsx("pre",{className:"text-xs overflow-x-auto",children:`{
  "host": "example.com",
  "type": "SPF",
  "value": "v=spf1 include:_spf.example.com ~all",
  "ttl": 3600,
  "status": "warning",
  "issues": ["Weak SPF policy (~all instead of -all)"]
}`})]})]})})]}),e.jsxs(s,{value:"dmarc-records",children:[e.jsx(i,{className:"text-left",children:"DMARC Records"}),e.jsx(r,{children:e.jsxs("div",{className:"space-y-4",children:[e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Description"}),e.jsx("p",{children:"Domain-based Message Authentication, Reporting, and Conformance (DMARC) records specify how email receivers should handle messages that fail SPF or DKIM verification. This check verifies proper DMARC implementation."})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Implementation Details"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-1",children:[e.jsx("li",{children:"Looks for DMARC record at _dmarc.domain.com"}),e.jsx("li",{children:"Checks for valid DMARC syntax"}),e.jsx("li",{children:"Evaluates DMARC policy strength (none vs quarantine vs reject)"}),e.jsx("li",{children:"Verifies percentage setting (pct=)"}),e.jsx("li",{children:"Validates reporting configuration"}),e.jsx("li",{children:"Checks for subdomain policy alignment"})]})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Security Implications"}),e.jsx("p",{children:"Without DMARC, even with SPF and DKIM, attackers can still successfully spoof emails. Weak DMARC policies (p=none) only monitor without taking action against suspicious emails."})]}),e.jsxs("div",{className:"bg-gray-50 p-3 rounded border border-gray-200",children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"API Response Example"}),e.jsx("pre",{className:"text-xs overflow-x-auto",children:`{
  "host": "_dmarc.example.com",
  "type": "DMARC",
  "value": "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
  "ttl": 3600,
  "status": "warning",
  "issues": ["Monitoring-only policy (p=none) does not protect against spoofing"]
}`})]})]})})]}),e.jsxs(s,{value:"dkim-records",children:[e.jsx(i,{className:"text-left",children:"DKIM Records"}),e.jsx(r,{children:e.jsxs("div",{className:"space-y-4",children:[e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Description"}),e.jsx("p",{children:"DomainKeys Identified Mail (DKIM) records contain public keys that receivers use to verify the cryptographic signatures of email messages. This check looks for proper DKIM implementation."})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Implementation Details"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-1",children:[e.jsx("li",{children:"Attempts to discover common DKIM selector names (default, google, etc.)"}),e.jsx("li",{children:"Checks DKIM record format for validity"}),e.jsx("li",{children:"Verifies key strength (minimum 1024 bits recommended)"}),e.jsx("li",{children:"Validates DKIM version number"}),e.jsx("li",{children:"Checks for testing mode flags that should not be in production"})]})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Security Implications"}),e.jsx("p",{children:"Without DKIM, emails lack cryptographic proof of authenticity. Weak DKIM keys can potentially be broken, allowing attackers to forge signatures."})]}),e.jsxs("div",{className:"bg-gray-50 p-3 rounded border border-gray-200",children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"API Response Example"}),e.jsx("pre",{className:"text-xs overflow-x-auto",children:`{
  "host": "default._domainkey.example.com",
  "type": "DKIM",
  "value": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC...",
  "ttl": 3600,
  "status": "warning",
  "issues": ["DKIM key length (1024 bits) is below recommended 2048 bits"]
}`})]})]})})]}),e.jsxs(s,{value:"enhanced-dmarc",children:[e.jsx(i,{className:"text-left",children:"Enhanced DMARC Analysis"}),e.jsx(r,{children:e.jsxs("div",{className:"space-y-4",children:[e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Description"}),e.jsx("p",{children:"This advanced check performs in-depth analysis of DMARC record configurations, looking at organizational domains, policy inheritance, and reporting configurations."})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Implementation Details"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-1",children:[e.jsx("li",{children:"Verifies DMARC record for both the domain and its organizational domains"}),e.jsx("li",{children:"Analyzes reporting configuration URLs and email addresses"}),e.jsx("li",{children:"Checks for proper report formatting options (aggregate vs forensic)"}),e.jsx("li",{children:"Validates reporting intervals"}),e.jsx("li",{children:"Examines subdomain policy inheritance with sp= tag"}),e.jsx("li",{children:"Assesses alignment mode strictness (strict vs relaxed)"})]})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Security Implications"}),e.jsx("p",{children:"Properly configured DMARC reporting is essential for monitoring and responding to email authentication failures and potential spoofing attempts. Misconfigured alignment settings may reduce security effectiveness."})]}),e.jsxs("div",{className:"bg-gray-50 p-3 rounded border border-gray-200",children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"API Response Example"}),e.jsx("pre",{className:"text-xs overflow-x-auto",children:`{
  "host": "_dmarc.example.com",
  "type": "DMARC_ANALYSIS",
  "value": "Enhanced DMARC Analysis",
  "status": "warning",
  "issues": ["No forensic reporting configured (missing ruf= tag)"]
}`})]})]})})]})]})}),e.jsx(m,{value:"advanced",children:e.jsxs(o,{type:"single",collapsible:!0,className:"w-full",children:[e.jsxs(s,{value:"dane",children:[e.jsx(i,{className:"text-left",children:"DANE (DNS-based Authentication of Named Entities)"}),e.jsx(r,{children:e.jsxs("div",{className:"space-y-4",children:[e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Description"}),e.jsx("p",{children:"DANE uses DNSSEC-protected DNS records to associate certificates with domain names, providing an additional layer of trust beyond the Certificate Authority system. This check verifies correct DANE implementation with TLSA records."})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Implementation Details"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-1",children:[e.jsx("li",{children:"Checks if DNSSEC is enabled (required for DANE)"}),e.jsx("li",{children:"Looks for TLSA records for common services (HTTPS, SMTP, IMAPS, POP3S, etc.)"}),e.jsx("li",{children:"Format: _port._tcp.domain (e.g., _443._tcp.example.com)"}),e.jsx("li",{children:"Validates TLSA record syntax (certificate usage, selector, matching type, cert data)"}),e.jsx("li",{children:"Verifies that records use recommended configurations"}),e.jsx("li",{children:"Examines usage fields (PKIX-TA, PKIX-EE, DANE-TA, DANE-EE)"})]})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Technical Implementation"}),e.jsx("p",{children:"DANE check performs the following operations:"}),e.jsxs("ol",{className:"list-decimal pl-5 space-y-1",children:[e.jsx("li",{children:"First verifies DNSSEC is enabled using dig +dnssec DNSKEY"}),e.jsx("li",{children:"Searches for TLSA records (DNS type 52) using specialized queries"}),e.jsx("li",{children:"For each service port (443/HTTPS, 25/SMTP, etc.), queries _port._tcp.domain"}),e.jsx("li",{children:"Parses TLSA record format: Usage Selector MatchingType CertificateData"}),e.jsx("li",{children:"Evaluates against best practices (DANE-EE (3) with SHA-256 (1) or SHA-512 (2))"})]})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Security Implications"}),e.jsx("p",{children:"DANE binds TLS certificates to DNS, reducing reliance on the Certificate Authority system. Without DANE, certificates can be compromised if any trusted CA is compromised. DANE requires DNSSEC to be enabled to provide true security benefits."})]}),e.jsxs("div",{className:"bg-gray-50 p-3 rounded border border-gray-200",children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"API Response Example"}),e.jsx("pre",{className:"text-xs overflow-x-auto",children:`{
  "host": "_443._tcp.example.com",
  "type": "DANE",
  "value": "TLSA record for HTTPS (443/tcp): Usage=DANE-EE, Selector=SPKI, Matching=SHA-256",
  "status": "secure"
}`})]})]})})]}),e.jsxs(s,{value:"caa-implementation",children:[e.jsx(i,{className:"text-left",children:"CAA Record Implementation"}),e.jsx(r,{children:e.jsxs("div",{className:"space-y-4",children:[e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Description"}),e.jsx("p",{children:"Certificate Authority Authorization (CAA) records specify which Certificate Authorities are permitted to issue certificates for a domain. This check verifies proper CAA implementation."})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Implementation Details"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-1",children:[e.jsx("li",{children:"Searches for CAA records (DNS type 257)"}),e.jsx("li",{children:"Validates CAA record format (flags tag value)"}),e.jsx("li",{children:"Checks for the three CAA tags: issue, issuewild, iodef"}),e.jsx("li",{children:"Verifies that authorized CAs are properly specified"}),e.jsx("li",{children:"Examines critical flag usage"}),e.jsx("li",{children:"Validates reporting mechanism (iodef tag)"})]})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Technical Implementation"}),e.jsx("p",{children:"CAA check performs the following operations:"}),e.jsxs("ol",{className:"list-decimal pl-5 space-y-1",children:[e.jsx("li",{children:"Queries for CAA records (DNS type 257)"}),e.jsx("li",{children:"Parses CAA record format: <flags> <tag> <value>"}),e.jsx("li",{children:"Validates recognized tag types (issue, issuewild, iodef)"}),e.jsxs("li",{children:["Checks for common configuration issues:",e.jsxs("ul",{className:"list-disc pl-5",children:[e.jsx("li",{children:"Empty issue/issuewild tags (block all issuance)"}),e.jsx("li",{children:"Critical flags with uncommon CAs"}),e.jsx("li",{children:"Missing issuewild tag (uses issue tag rules)"}),e.jsx("li",{children:"Missing iodef reporting mechanism"})]})]})]})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Security Implications"}),e.jsx("p",{children:"CAA records provide a defense-in-depth mechanism to prevent unauthorized certificate issuance for a domain. Without CAA records, any publicly trusted CA can issue certificates for any domain, increasing the risk of fraudulent certificates."})]}),e.jsxs("div",{className:"bg-gray-50 p-3 rounded border border-gray-200",children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"API Response Example"}),e.jsx("pre",{className:"text-xs overflow-x-auto",children:`{
  "host": "example.com",
  "type": "CAA_IMPLEMENTATION",
  "value": "CAA issue="letsencrypt.org"",
  "status": "warning",
  "issues": ["No iodef reporting mechanism defined"]
}`})]})]})})]}),e.jsxs(s,{value:"tcp-fallback",children:[e.jsx(i,{className:"text-left",children:"TCP Fallback Testing"}),e.jsx(r,{children:e.jsxs("div",{className:"space-y-4",children:[e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Description"}),e.jsx("p",{children:"This check tests if DNS servers properly support TCP fallback for large responses. DNS traditionally uses UDP, but falls back to TCP when responses exceed 512 bytes (or 4096 bytes with EDNS0)."})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Implementation Details"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-1",children:[e.jsx("li",{children:"Identifies all authoritative nameservers for the domain"}),e.jsx("li",{children:"Tests basic TCP connectivity to port 53 on each nameserver"}),e.jsx("li",{children:"Tests explicit DNS queries over TCP"}),e.jsx("li",{children:"Attempts to trigger large DNS responses that would cause UDP truncation"}),e.jsx("li",{children:"Verifies proper TCP fallback behavior"})]})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Technical Implementation"}),e.jsx("p",{children:"TCP Fallback testing performs the following operations:"}),e.jsxs("ol",{className:"list-decimal pl-5 space-y-1",children:[e.jsx("li",{children:"Tests basic TCP socket connection to port 53 of nameservers"}),e.jsx("li",{children:"Runs explicit TCP-only DNS queries (dig +tcp)"}),e.jsxs("li",{children:["Generates large DNS responses by:",e.jsxs("ul",{className:"list-disc pl-5",children:[e.jsx("li",{children:"Requesting multiple record types simultaneously (ANY query)"}),e.jsx("li",{children:"Setting a small buffer size (bufsize=512)"}),e.jsx("li",{children:"Checking for truncation flag (tc: 1) in responses"}),e.jsx("li",{children:"Verifying that subsequent TCP queries succeed"})]})]})]})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Security Implications"}),e.jsx("p",{children:"TCP fallback is essential for DNSSEC and other modern DNS features that often produce large responses. Without TCP fallback support, DNSSEC validation can fail, security extensions may not work, and DNS records might be incomplete due to truncation."})]}),e.jsxs("div",{className:"bg-gray-50 p-3 rounded border border-gray-200",children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"API Response Example"}),e.jsx("pre",{className:"text-xs overflow-x-auto",children:`{
  "host": "ns1.example.com",
  "type": "TCP_FALLBACK",
  "value": "Nameserver supports TCP fallback for large DNS responses",
  "status": "secure"
}`})]})]})})]}),e.jsxs(s,{value:"dnssec",children:[e.jsx(i,{className:"text-left",children:"DNSSEC"}),e.jsx(r,{children:e.jsxs("div",{className:"space-y-4",children:[e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Description"}),e.jsx("p",{children:"DNSSEC (DNS Security Extensions) adds cryptographic signatures to DNS records to prevent tampering and spoofing. This check verifies proper DNSSEC implementation."})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Implementation Details"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-1",children:[e.jsx("li",{children:"Checks for presence of DNSKEY records"}),e.jsx("li",{children:"Verifies DS (Delegation Signer) records in parent zone"}),e.jsx("li",{children:"Validates signatures using RRSIG records"}),e.jsx("li",{children:"Checks for proper key rollover practices"}),e.jsx("li",{children:"Verifies NSEC or NSEC3 records for authenticated denial of existence"})]})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Security Implications"}),e.jsx("p",{children:"Without DNSSEC, DNS is vulnerable to cache poisoning and spoofing attacks. DNSSEC provides authentication of DNS data, ensuring that responses come from the authoritative source and haven't been tampered with."})]}),e.jsxs("div",{className:"bg-gray-50 p-3 rounded border border-gray-200",children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"API Response Example"}),e.jsx("pre",{className:"text-xs overflow-x-auto",children:`{
  "host": "example.com",
  "type": "DNSSEC",
  "value": "DNSSEC properly implemented with valid signatures",
  "status": "secure"
}`})]})]})})]}),e.jsxs(s,{value:"dnssec-algorithm",children:[e.jsx(i,{className:"text-left",children:"DNSSEC Algorithm Strength"}),e.jsx(r,{children:e.jsxs("div",{className:"space-y-4",children:[e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Description"}),e.jsx("p",{children:"This check analyzes the cryptographic algorithms used in DNSSEC implementations to identify weak or deprecated algorithms that may pose security risks."})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Implementation Details"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-1",children:[e.jsx("li",{children:"Identifies the algorithm number used in DNSKEY records"}),e.jsx("li",{children:"Compares against IANA's list of DNS security algorithm numbers"}),e.jsx("li",{children:"Flags deprecated or weak algorithms (RSA/MD5, DSA)"}),e.jsx("li",{children:"Recommends secure alternatives (RSA/SHA-256, ECDSA, Ed25519)"}),e.jsx("li",{children:"Checks key lengths for RSA algorithms"})]})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Security Implications"}),e.jsx("p",{children:"Using outdated cryptographic algorithms in DNSSEC can weaken its security guarantees. As computing power increases and cryptographic attacks improve, algorithms that were once secure may become vulnerable."})]}),e.jsxs("div",{className:"bg-gray-50 p-3 rounded border border-gray-200",children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"API Response Example"}),e.jsx("pre",{className:"text-xs overflow-x-auto",children:`{
  "host": "example.com",
  "type": "DNSSEC_ALGORITHM",
  "value": "DNSSEC using algorithm 8 (RSA/SHA-256)",
  "status": "secure"
}`})]})]})})]}),e.jsxs(s,{value:"nsec3-params",children:[e.jsx(i,{className:"text-left",children:"NSEC3 Parameters"}),e.jsx(r,{children:e.jsxs("div",{className:"space-y-4",children:[e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Description"}),e.jsx("p",{children:"NSEC3 is used in DNSSEC to provide authenticated denial of existence while preventing zone enumeration. This check analyzes NSEC3 parameter choices for security and performance issues."})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Implementation Details"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-1",children:[e.jsx("li",{children:"Checks for presence of NSEC3PARAM records"}),e.jsx("li",{children:"Verifies hash algorithm (currently only SHA-1 is defined)"}),e.jsx("li",{children:"Examines opt-out flag usage"}),e.jsx("li",{children:"Validates iteration count (recommended: 0-100)"}),e.jsx("li",{children:"Checks salt length and value"})]})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Security Implications"}),e.jsx("p",{children:"Improper NSEC3 configuration can either weaken security (too few iterations) or cause performance problems (too many iterations). Extremely high iteration counts can also be used for denial-of-service attacks."})]}),e.jsxs("div",{className:"bg-gray-50 p-3 rounded border border-gray-200",children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"API Response Example"}),e.jsx("pre",{className:"text-xs overflow-x-auto",children:`{
  "host": "example.com",
  "type": "NSEC3_PARAMS",
  "value": "NSEC3 parameters: 1 0 10 ABCDEF",
  "status": "secure"
}`})]})]})})]}),e.jsxs(s,{value:"zone-transfer",children:[e.jsx(i,{className:"text-left",children:"Zone Transfer Vulnerability"}),e.jsx(r,{children:e.jsxs("div",{className:"space-y-4",children:[e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Description"}),e.jsx("p",{children:"This check tests if a domain's DNS servers allow zone transfers (AXFR) to unauthorized parties, which could expose the complete list of DNS records."})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Implementation Details"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-1",children:[e.jsx("li",{children:"Identifies all authoritative nameservers for the domain"}),e.jsx("li",{children:"Attempts AXFR (zone transfer) requests to each nameserver"}),e.jsx("li",{children:"Verifies transfer restrictions are properly implemented"}),e.jsx("li",{children:"Checks for partial zone data leakage"})]})]}),e.jsxs("div",{children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"Security Implications"}),e.jsx("p",{children:"Unrestricted zone transfers allow attackers to map your entire DNS infrastructure, including internal hostnames, IP addresses, and service configurations. This information can be used for network reconnaissance before attacks."})]}),e.jsxs("div",{className:"bg-gray-50 p-3 rounded border border-gray-200",children:[e.jsx("h4",{className:"font-semibold text-blue-700",children:"API Response Example"}),e.jsx("pre",{className:"text-xs overflow-x-auto",children:`{
  "host": "ns1.example.com",
  "type": "AXFR",
  "value": "Zone transfers properly restricted",
  "status": "secure"
}`})]})]})})]})]})})]})]})]})]}),S=()=>e.jsx("div",{className:"container mx-auto px-4 py-8",children:e.jsxs("div",{className:"max-w-4xl mx-auto",children:[e.jsx("h2",{className:"text-2xl font-bold mb-4 text-blue-600",children:"Go Scanner Implementation Guide"}),e.jsx("div",{className:"mb-8",children:e.jsx("p",{className:"text-gray-700 mb-4",children:"This document provides comprehensive implementation details for the Go-based DNS scanner service to be deployed at api.dnsaudit.io. It covers the architecture, data models, algorithms, and specific implementation guidance for each DNS check."})}),e.jsxs("div",{className:"bg-blue-50 p-6 rounded-lg border border-blue-200 mb-8",children:[e.jsx("h3",{className:"font-semibold text-lg mb-2",children:"Go Scanner Prompt Template"}),e.jsx("p",{className:"mb-4",children:"Use this prompt when setting up the new Go-based scanner:"}),e.jsx("div",{className:"bg-white p-4 rounded-md border border-gray-300 whitespace-pre-wrap overflow-auto text-xs font-mono max-h-96",children:`# DNSAudit.io Go Scanner Service

Build a high-performance DNS security scanner API in Go with these requirements:

## Core Architecture 
- Create a REST API with the Echo framework
- Implement modular check system where each security check is a separate component
- Use goroutines for parallel execution of DNS checks
- Support caching of DNS results using in-memory cache, with optional Redis support
- All checks must use real DNS lookups, no simulated data

## API Endpoints
- GET /api/v1/scan?domain={domain}&records={recordTypes} (primary scan endpoint)
- GET /api/v1/history/{domain}?limit={limit} (retrieve past scan results)
- GET /api/v1/logs (list domains with active scan logs)
- GET /api/v1/logs/{domain} (get detailed scan logs for domain)
- GET /api/v1/health (health check endpoint)

## Standard Record Checks (A, AAAA, MX, NS, TXT, CNAME)
Implement checks for all standard DNS record types with validation of:
- Record presence and proper formatting
- Appropriate TTL values
- IPv4/IPv6 address validity
- Nameserver redundancy (min 2 NS records on different networks)
- MX record priority and security configurations

## Email Security Checks (SPF, DKIM, DMARC)
Implement comprehensive email security validation:
- SPF: Check syntax, policy strength (~all vs -all), DNS lookup limits
- DKIM: Discover common selectors, verify key strength (min 1024 bits)
- DMARC: Validate policy strength, reporting configuration, subdomain policy

## Advanced Security Checks
Implement these critical security checks:

1. DANE (DNS-based Authentication of Named Entities)
   - Verify DNSSEC is enabled (required for DANE)
   - Check for TLSA records for common services (HTTPS, SMTP, etc.)
   - Validate record format and security configurations
   - Check for DANE-EE with SHA-256/SHA-512 (recommended secure config)

2. CAA Record Implementation
   - Verify CAA records restrict certificate issuance to authorized CAs
   - Check for proper tag usage (issue, issuewild, iodef)
   - Validate critical flag usage
   - Check reporting mechanism configuration

3. TCP Fallback Testing
   - Test TCP connectivity to port 53 on nameservers
   - Force large DNS responses to trigger TCP fallback
   - Verify proper handling of truncated responses
   - Check across all authoritative nameservers

4. DNSSEC Implementation
   - Verify DNSKEY and DS records existence
   - Validate signature chains
   - Check for NSEC/NSEC3 authenticated denial of existence

5. DNSSEC Algorithm Strength
   - Identify cryptographic algorithms used
   - Flag weak algorithms (RSA/MD5, DSA)
   - Recommend strong alternatives (ECDSA, Ed25519)
   - Check key lengths for RSA algorithms

6. NSEC3 Parameters
   - Validate hash algorithm (SHA-1)
   - Check iteration count (recommend 0-100)
   - Verify salt length and uniqueness

7. Zone Transfer Vulnerability
   - Test for unrestricted AXFR access
   - Check transfer restrictions across all nameservers

8. DNS Amplification Risk
   - Check for open recursion
   - Test response sizes for common query types
   - Flag potential for reflection attacks

9. Subdomain Takeover Detection
   - Check for dangling CNAME records
   - Validate all CNAME targets resolve

10. DNS CVE Testing
    - Fingerprint DNS server software
    - Check for known vulnerabilities
    - Provide specific CVE references

## Performance Requirements
- Support 100+ concurrent scans
- Complete basic scan in <2 seconds (cached), <10 seconds (uncached)
- Rate limiting: 30 requests per minute per IP
- Implement circuit breakers for unreliable nameservers
- Log performance metrics per check

## Security Requirements
- API key authentication for all endpoints
- HTTPS required for all connections
- Properly handle timeout and cancellation
- Validate and sanitize all user input
- Implement proper error handling
`})]}),e.jsxs("div",{className:"mb-12",children:[e.jsx("h3",{className:"text-xl font-semibold mb-4 text-blue-700",children:"Data Models"}),e.jsxs("div",{className:"space-y-4",children:[e.jsx("p",{className:"text-gray-700",children:"The following Go structs should be implemented to match our current TypeScript schema:"}),e.jsx("div",{className:"bg-gray-50 p-4 rounded-md font-mono text-sm overflow-auto border border-gray-200",children:`// BasicModels.go

// StatusType represents security status levels
type StatusType string

const (
    StatusSecure   StatusType = "secure"
    StatusWarning  StatusType = "warning"
    StatusCritical StatusType = "critical"
    StatusInfo     StatusType = "info"
)

// RecordType represents the type of DNS record or security check
type RecordType string

// Define all standard record types
const (
    RecordTypeA      RecordType = "A"
    RecordTypeAAAA   RecordType = "AAAA"
    RecordTypeMX     RecordType = "MX" 
    RecordTypeTXT    RecordType = "TXT"
    RecordTypeNS     RecordType = "NS"
    RecordTypeCNAME  RecordType = "CNAME"
    RecordTypeSPF    RecordType = "SPF"
    RecordTypeDMARC  RecordType = "DMARC"
    RecordTypeDKIM   RecordType = "DKIM"
    RecordTypeCAA    RecordType = "CAA"
    RecordTypeSRV    RecordType = "SRV"
)

// Define all security check types
const (
    CheckTypeAXFR               RecordType = "AXFR"
    CheckTypeDNSSEC             RecordType = "DNSSEC"
    CheckTypeRebinding          RecordType = "REBINDING"
    CheckTypeTakeover           RecordType = "TAKEOVER"
    CheckTypeAmplification      RecordType = "AMPLIFICATION"
    CheckTypeService            RecordType = "SERVICE"
    CheckTypeDMARCAnalysis      RecordType = "DMARC_ANALYSIS"
    CheckTypeCVE                RecordType = "CVE"
    CheckTypeRecursion          RecordType = "RECURSION"
    CheckTypeDNSTLS             RecordType = "DNS_TLS"
    CheckTypeQueryMin           RecordType = "QUERY_MIN"
    CheckTypeRateLimit          RecordType = "RATE_LIMIT"
    CheckTypeDNSCookies         RecordType = "DNS_COOKIES"
    CheckTypeDNSResponseSize    RecordType = "DNS_RESPONSE_SIZE"
    CheckTypeTTLAnalysis        RecordType = "TTL_ANALYSIS"
    CheckTypeDNSSECAlgorithm    RecordType = "DNSSEC_ALGORITHM"
    CheckTypeNSEC3Params        RecordType = "NSEC3_PARAMS"
    CheckTypeDANE               RecordType = "DANE"
    CheckTypeCAAImplementation  RecordType = "CAA_IMPLEMENTATION"
    CheckTypeTCPFallback        RecordType = "TCP_FALLBACK"
)

// DnsRecord represents a single DNS record or check result
type DnsRecord struct {
    Host    string      \`json:"host"\`
    Type    RecordType  \`json:"type"\`
    Value   string      \`json:"value"\`
    TTL     *int        \`json:"ttl,omitempty"\`
    Status  StatusType  \`json:"status"\`
    Issues  []string    \`json:"issues,omitempty"\`
}

// Issue represents a security issue found during scanning
type Issue struct {
    Type           StatusType  \`json:"type"\`
    RecordType     RecordType  \`json:"recordType"\`
    Description    string      \`json:"description"\`
    Recommendation string      \`json:"recommendation"\`
}

// ScanResult represents the complete result of a domain scan
type ScanResult struct {
    Status        string                 \`json:"status"\`
    Domain        string                 \`json:"domain"\`
    ScanDate      string                 \`json:"scanDate"\`
    SecurityScore int                    \`json:"securityScore"\`
    Summary       Summary                \`json:"summary"\`
    Records       map[string][]DnsRecord \`json:"records"\`
    Issues        []Issue                \`json:"issues"\`
}

// Summary provides a count of issues by severity
type Summary struct {
    CriticalIssues int \`json:"criticalIssues"\`
    Warnings       int \`json:"warnings"\`
    Passed         int \`json:"passed"\`
}

// ScanRequest represents an incoming scan request
type ScanRequest struct {
    Domain      string      \`json:"domain" validate:"required"\`
    RecordTypes []string    \`json:"record_types,omitempty"\`
}

// NormalizeDomain standardizes domain input
func NormalizeDomain(input string) string {
    // Convert to lowercase
    normalized := strings.ToLower(input)
    
    // Remove any protocol (http://, https://, etc.)
    normalized = regexp.MustCompile("^(https?://)?").ReplaceAllString(normalized, "")
    
    // Remove www. prefix
    normalized = regexp.MustCompile("^www\\.").ReplaceAllString(normalized, "")
    
    // Remove any trailing slash or path
    parts := strings.Split(normalized, "/")
    normalized = parts[0]
    
    return normalized
}`})]})]}),e.jsxs("div",{className:"mb-12",children:[e.jsx("h3",{className:"text-xl font-semibold mb-4 text-blue-700",children:"Scanner Core Interface"}),e.jsxs("div",{className:"space-y-4",children:[e.jsx("p",{className:"text-gray-700",children:"Implement the following core scanner interfaces that all check modules will implement:"}),e.jsx("div",{className:"bg-gray-50 p-4 rounded-md font-mono text-sm overflow-auto border border-gray-200",children:`// Scanner.go

// Scanner defines the interface for DNS scanners
type Scanner interface {
    Scan(ctx context.Context, domain string, recordTypes []string) (ScanResult, error)
}

// Check defines the interface for individual DNS checks
type Check interface {
    // Name returns the check's identifier
    Name() string
    
    // RecordType returns the type of records this check handles
    RecordType() RecordType
    
    // Run performs the check and returns results
    Run(ctx context.Context, domain string, issues *[]Issue) ([]DnsRecord, error)
}

// DnsScanner implements the Scanner interface
type DnsScanner struct {
    cache           Cache
    standardChecks  []Check
    securityChecks  []Check
}

// NewScanner creates a new DNS scanner with all registered checks
func NewScanner(cache Cache) *DnsScanner {
    s := &DnsScanner{
        cache: cache,
    }
    
    // Register standard record type checks
    s.standardChecks = []Check{
        NewARecordCheck(cache),
        NewAAAARecordCheck(cache),
        NewMXRecordCheck(cache),
        NewTXTRecordCheck(cache),
        NewNSRecordCheck(cache),
        NewCNAMERecordCheck(cache),
        NewSPFRecordCheck(cache),
        NewDMARCRecordCheck(cache),
        NewDKIMRecordCheck(cache),
    }
    
    // Register security checks
    s.securityChecks = []Check{
        NewZoneTransferCheck(cache),
        NewDNSSECCheck(cache),
        NewDNSRebindingCheck(cache),
        NewSubdomainTakeoverCheck(cache),
        NewDNSAmplificationCheck(cache),
        NewServiceDiscoveryCheck(cache),
        NewDMARCAnalysisCheck(cache),
        NewDNSCVECheck(cache),
        NewDNSOpenRecursionCheck(cache),
        NewDNSOverTLSCheck(cache),
        NewDNSQueryMinimizationCheck(cache),
        NewDNSCookiesCheck(cache),
        NewDNSResponseSizeCheck(cache),
        NewDNSTTLAnalysisCheck(cache),
        NewDNSSECAlgorithmCheck(cache),
        NewNSEC3ParametersCheck(cache),
        NewDANECheck(cache),
        NewCAAImplementationCheck(cache),
        NewTCPFallbackCheck(cache),
    }
    
    return s
}

// Scan performs a complete domain scan
func (s *DnsScanner) Scan(ctx context.Context, domain string, recordTypes []string) (ScanResult, error) {
    // Implementation of the main scan function that:
    // 1. Normalizes domain
    // 2. Runs security checks in parallel using goroutines
    // 3. Runs standard record checks in parallel
    // 4. Aggregates results and calculates security score
    // 5. Returns complete scan result
    
    // This implementation should closely match the logic in the 
    // existing scanDomain function in dns-utils.ts
}`})]})]}),e.jsxs("div",{className:"mb-12",children:[e.jsx("h3",{className:"text-xl font-semibold mb-4 text-blue-700",children:"Cache Implementation"}),e.jsxs("div",{className:"space-y-4",children:[e.jsx("p",{className:"text-gray-700",children:"Implement an efficient caching system to improve performance:"}),e.jsx("div",{className:"bg-gray-50 p-4 rounded-md font-mono text-sm overflow-auto border border-gray-200",children:`// Cache.go

// CacheType defines different types of cached data
type CacheType string

const (
    CacheTypeDefault     CacheType = "default"
    CacheTypeNameserver  CacheType = "nameserver"
    CacheTypeBoolean     CacheType = "boolean"
    CacheTypeString      CacheType = "string"
    CacheTypeArray       CacheType = "array"
)

// Cache defines the interface for DNS result caching
type Cache interface {
    // Get retrieves a value from cache, returns nil if not found
    Get(key string, cacheType CacheType) interface{}
    
    // GetTyped retrieves a typed value from cache with type assertion
    GetTyped[T any](key string, cacheType CacheType) (T, bool)
    
    // Set stores a value in cache with TTL in seconds
    Set(key string, value interface{}, ttlSeconds int, cacheType CacheType)
    
    // Delete removes a value from cache
    Delete(key string)
    
    // Stats returns cache statistics
    Stats() CacheStats
}

// CacheStats provides metrics about cache performance
type CacheStats struct {
    Hits      int64
    Misses    int64
    Size      int64
    Items     int
}

// Helper methods for getting cache hit rate etc.
func (s CacheStats) HitRate() float64 {
    total := s.Hits + s.Misses
    if total == 0 {
        return 0
    }
    return float64(s.Hits) / float64(total)
}

// MemoryCache implements Cache using in-memory storage
type MemoryCache struct {
    data     map[string]CacheItem
    stats    CacheStats
    maxSize  int64
    mu       sync.RWMutex
}

type CacheItem struct {
    Value       interface{}
    ExpiresAt   time.Time
    Size        int64
    Type        CacheType
}

// NewMemoryCache creates a new memory cache with max size in MB
func NewMemoryCache(maxSizeMB int) *MemoryCache {
    return &MemoryCache{
        data:    make(map[string]CacheItem),
        maxSize: int64(maxSizeMB) * 1024 * 1024,
    }
}

// Implementation of Cache interface methods for MemoryCache
// ...

// RedisCache implements Cache using Redis
type RedisCache struct {
    client  *redis.Client
    stats   CacheStats
    prefix  string
}

// NewRedisCache creates a new Redis-backed cache
func NewRedisCache(redisURL, keyPrefix string) (*RedisCache, error) {
    // Parse Redis URL and create client
    // ...
    return &RedisCache{}, nil
}

// TieredCache implements Cache using both memory and Redis
// with memory as a fast first-level cache
type TieredCache struct {
    memory  *MemoryCache
    redis   *RedisCache
    stats   CacheStats
}

// NewTieredCache creates a new tiered cache system
func NewTieredCache(memoryMaxSizeMB int, redisURL, keyPrefix string) (*TieredCache, error) {
    // Create memory and Redis caches
    // ...
    return &TieredCache{}, nil
}

// Implement cache interface with tiered priority:
// 1. Check memory cache first
// 2. If not in memory, check Redis
// 3. If found in Redis, store in memory for next access
// 4. If not found, return nil

func (tc *TieredCache) Get(key string) (interface{}, bool) {
    // Implementation logic
    return nil, false
}

func (tc *TieredCache) Set(key string, value interface{}, ttl time.Duration) {
    // Implementation logic
}

// DNSCache.go (higher-level domain-specific caching)

// DNSCache provides domain-specific caching for DNS lookups
type DNSCache struct {
    cache          Cache
    defaultTTL     time.Duration
    cleanupEnabled bool
}

// CacheEntry represents a single cached item
type CacheEntry struct {
    key        string
    value      interface{}
    expiration time.Time
}

// NewDNSCache creates a new DNS-specific cache
func NewDNSCache(cache Cache, defaultTTLSeconds int, enableCleanup bool) *DNSCache {
    dnsCache := &DNSCache{
        cache:   cache,
        defaultTTL: time.Duration(defaultTTLSeconds) * time.Second,
        cleanupEnabled: enableCleanup,
    }
    
    if enableCleanup {
        go dnsCache.startCleanupLoop()
    }
    
    return dnsCache
}

// CacheDNSRecords stores DNS records in cache
func (c *DNSCache) CacheDNSRecords(domain string, recordType string, records []DnsRecord) {
    // Implementation
}

// GetCachedDNSRecords retrieves cached DNS records
func (c *DNSCache) GetCachedDNSRecords(domain string, recordType string) ([]DnsRecord, bool) {
    // Implementation
    return nil, false
}

// CacheDNSScan stores a complete scan result
func (c *DNSCache) CacheDNSScan(domain string, result ScanResult) {
    // Implementation
}

// GetCachedDNSScan retrieves a cached scan result
func (c *DNSCache) GetCachedDNSScan(domain string) (ScanResult, bool) {
    // Implementation
    return ScanResult{}, false
}

// startCleanupLoop runs a periodic cache cleanup
func (c *DNSCache) startCleanupLoop() {
    // Implementation
}

// Helper functions
func createCacheKey(domain, recordType string) string {
    return fmt.Sprintf("dns:%s:%s", strings.ToLower(domain), recordType)
}

func createScanCacheKey(domain string) string {
    return fmt.Sprintf("scan:%s", strings.ToLower(domain))
}`})]})]}),e.jsxs("div",{className:"mb-12",children:[e.jsx("h3",{className:"text-xl font-semibold mb-4 text-blue-700",children:"DANE Implementation"}),e.jsxs("div",{className:"space-y-4",children:[e.jsx("p",{className:"text-gray-700",children:"DNS-based Authentication of Named Entities (DANE) provides a way to bind X.509 certificates to DNS names using DNSSEC. Implement the following for DANE checks:"}),e.jsx("div",{className:"bg-gray-50 p-4 rounded-md font-mono text-sm overflow-auto border border-gray-200",children:`// dane.go

// DANE TLSA record formats:
// Usage values (first field):
// 0 = PKIX-TA: CA constraint
// 1 = PKIX-EE: Service certificate constraint
// 2 = DANE-TA: Trust anchor assertion
// 3 = DANE-EE: Domain-issued certificate (most secure)
//
// Selector values (second field):
// 0 = Cert: Full certificate
// 1 = SPKI: SubjectPublicKeyInfo
//
// Matching Type values (third field):
// 0 = Full: No hash used
// 1 = SHA-256: SHA-256 hash
// 2 = SHA-512: SHA-512 hash

// DANECheck implements the Check interface for DANE validation
type DANECheck struct {
    cache       Cache
    dnsClient   *dns.Client
}

func NewDANECheck(cache Cache) *DANECheck {
    return &DANECheck{
        cache:     cache,
        dnsClient: &dns.Client{},
    }
}

func (c *DANECheck) Name() string {
    return "DANE"
}

func (c *DANECheck) RecordType() RecordType {
    return CheckTypeDANE
}

func (c *DANECheck) Run(ctx context.Context, domain string, issues *[]Issue) ([]DnsRecord, error) {
    var records []DnsRecord
    
    // First check if DNSSEC is enabled for the domain, as it's required for DANE
    dnssecEnabled, err := c.checkDNSSECEnabled(domain)
    if err != nil {
        return records, err
    }
    
    // If DNSSEC is not enabled, DANE cannot be used securely
    if !dnssecEnabled {
        *issues = append(*issues, Issue{
            Type:           StatusWarning,
            RecordType:     CheckTypeDANE,
            Description:    "DNSSEC is required for secure DANE implementation but is not enabled for this domain",
            Recommendation: "Enable DNSSEC before implementing DANE",
        })
        
        records = append(records, DnsRecord{
            Host:   domain,
            Type:   CheckTypeDANE,
            Value:  "DNSSEC not enabled",
            Status: StatusWarning,
            Issues: []string{"DNSSEC not enabled for domain"},
        })
        
        return records, nil
    }
    
    // Check for TLSA records for common services
    services := []string{"_443._tcp", "_25._tcp", "_587._tcp", "_465._tcp", "_993._tcp", "_995._tcp"}
    
    for _, service := range services {
        tlsaRecords, err := c.queryTLSARecords(service + "." + domain)
        if err != nil {
            continue // Just skip this service if lookup fails
        }
        
        if len(tlsaRecords) == 0 {
            continue // No records for this service
        }
        
        for _, tlsa := range tlsaRecords {
            status, issues := c.analyzeDANERecord(tlsa)
            
            records = append(records, DnsRecord{
                Host:   service + "." + domain,
                Type:   CheckTypeDANE,
                Value:  tlsa.String(),
                Status: status,
                Issues: issues,
            })
        }
    }
    
    // If no TLSA records found for any service, add an info record
    if len(records) == 0 {
        records = append(records, DnsRecord{
            Host:   domain,
            Type:   CheckTypeDANE,
            Value:  "No TLSA records found",
            Status: StatusInfo,
            Issues: []string{"No DANE TLSA records configured for common services"},
        })
        
        *issues = append(*issues, Issue{
            Type:           StatusInfo,
            RecordType:     CheckTypeDANE,
            Description:    "No DANE TLSA records found for common services",
            Recommendation: "Consider implementing DANE for enhanced TLS certificate validation",
        })
    }
    
    return records, nil
}

func (c *DANECheck) queryTLSARecords(hostname string) ([]*dns.TLSA, error) {
    // Implementation to query TLSA records using dns package
    // ...
    return []*dns.TLSA{}, nil
}

func (c *DANECheck) checkDNSSECEnabled(domain string) (bool, error) {
    // Implementation to check for DNSSEC
    // ...
    return false, nil
}

func (c *DANECheck) analyzeDANERecord(tlsa *dns.TLSA) (StatusType, []string) {
    var issues []string
    var status StatusType = StatusSecure
    
    // Check for best practice DANE configurations
    
    // Analyze usage field (certificate usage)
    switch tlsa.Usage {
    case 0: // PKIX-TA
        issues = append(issues, "Using PKIX-TA (0) mode which relies on the CA system")
        status = StatusInfo
    case 1: // PKIX-EE
        issues = append(issues, "Using PKIX-EE (1) mode which relies on the CA system")
        status = StatusInfo
    case 2: // DANE-TA
        // This is good but not the strongest
        status = StatusSecure
    case 3: // DANE-EE
        // This is the most secure option
        status = StatusSecure
    default:
        issues = append(issues, fmt.Sprintf("Unknown TLSA usage value: %d", tlsa.Usage))
        status = StatusWarning
    }
    
    // Analyze selector field
    if tlsa.Selector != 1 {
        issues = append(issues, "Using full certificate (0) selector instead of SPKI (1)")
        if status == StatusSecure {
            status = StatusInfo
        }
    }
    
    // Analyze matching type field
    if tlsa.MatchingType == 0 {
        issues = append(issues, "Using full certificate data (0) instead of a secure hash")
        status = StatusWarning
    } else if tlsa.MatchingType != 1 && tlsa.MatchingType != 2 {
        issues = append(issues, fmt.Sprintf("Unknown TLSA matching type: %d", tlsa.MatchingType))
        status = StatusWarning
    }
    
    // If we have the ideal configuration: DANE-EE (3) + SPKI (1) + SHA-256/512 (1/2)
    if tlsa.Usage == 3 && tlsa.Selector == 1 && (tlsa.MatchingType == 1 || tlsa.MatchingType == 2) {
        issues = append(issues, "Using recommended secure DANE configuration")
    }
    
    return status, issues
}`})]})]}),e.jsxs("div",{className:"mb-12",children:[e.jsx("h3",{className:"text-xl font-semibold mb-4 text-blue-700",children:"CAA Implementation"}),e.jsxs("div",{className:"space-y-4",children:[e.jsx("p",{className:"text-gray-700",children:"Certificate Authority Authorization (CAA) records allow domain owners to specify which certificate authorities are allowed to issue certificates for their domain. Implement the following for CAA checks:"}),e.jsx("div",{className:"bg-gray-50 p-4 rounded-md font-mono text-sm overflow-auto border border-gray-200",children:`// caa_implementation.go

// Common CA issuers
var knownCAs = map[string]bool{
    "letsencrypt.org":        true,
    "pki.goog":               true,
    "amazon.com":             true,
    "amazontrust.com":        true,
    "awstrust.com":           true,
    "sectigo.com":            true,
    "digicert.com":           true,
    "globalsign.com":         true,
    "godaddy.com":            true,
    "entrust.net":            true,
    "ssl.com":                true,
    "identrust.com":          true,
    "buypass.com":            true,
    "buypass.no":             true,
    "comodo.com":             true,
    "comodoca.com":           true,
    "usertrust.com":          true,
    "trust-provider.com":     true,
    "actalis.it":             true,
    "certsign.ro":            true,
    "harica.gr":              true,
}

// CAAImplementationCheck implements the Check interface for CAA validation
type CAAImplementationCheck struct {
    cache     Cache
    dnsClient *dns.Client
}

func NewCAAImplementationCheck(cache Cache) *CAAImplementationCheck {
    return &CAAImplementationCheck{
        cache:     cache,
        dnsClient: &dns.Client{},
    }
}

func (c *CAAImplementationCheck) Name() string {
    return "CAA Implementation"
}

func (c *CAAImplementationCheck) RecordType() RecordType {
    return CheckTypeCAAImplementation
}

func (c *CAAImplementationCheck) Run(ctx context.Context, domain string, issues *[]Issue) ([]DnsRecord, error) {
    var records []DnsRecord
    
    // Query the domain for CAA records
    caaRecords, err := c.queryCAARecords(domain)
    if err != nil {
        // Ignore resolution errors - absence of records is not an error for CAA
        if !strings.Contains(err.Error(), "NXDOMAIN") && !strings.Contains(err.Error(), "no such host") {
            return nil, err
        }
    }
    
    // If there are no CAA records, check parent domains according to RFC 8659
    if len(caaRecords) == 0 {
        // Try to find in parent domains
        parentDomain := getParentDomain(domain)
        for parentDomain != "" {
            parentCAARecords, err := c.queryCAARecords(parentDomain)
            if err == nil && len(parentCAARecords) > 0 {
                caaRecords = parentCAARecords
                break
            }
            parentDomain = getParentDomain(parentDomain)
        }
    }
    
    // If still no CAA records found, recommend implementing them
    if len(caaRecords) == 0 {
        *issues = append(*issues, Issue{
            Type:           StatusWarning,
            RecordType:     CheckTypeCAAImplementation,
            Description:    "No CAA records found. CAA records help prevent unauthorized certificate issuance.",
            Recommendation: "Implement CAA records to restrict which CAs can issue certificates for your domain.",
        })
        
        records = append(records, DnsRecord{
            Host:   domain,
            Type:   CheckTypeCAAImplementation,
            Value:  "No CAA records found",
            Status: StatusWarning,
            Issues: []string{"Missing CAA records"},
        })
        
        return records, nil
    }
    
    var issueRecordFound, issuewildRecordFound, iodefRecordFound bool
    var validIssuers []string
    var issues []string
    
    for _, caaRecord := range caaRecords {
        status := StatusSecure
        recordIssues := []string{}
        
        switch caaRecord.Tag {
        case "issue":
            issueRecordFound = true
            
            // Check if the issuer is known
            if caaRecord.Value != "" && !c.isKnownCA(caaRecord.Value) {
                recordIssues = append(recordIssues, fmt.Sprintf("Issuer '%s' is not recognized as a common CA", caaRecord.Value))
                status = StatusInfo
            }
            
            if caaRecord.Value != "" {
                validIssuers = append(validIssuers, caaRecord.Value)
            }
            
        case "issuewild":
            issuewildRecordFound = true
            
            if caaRecord.Value != "" && !c.isKnownCA(caaRecord.Value) {
                recordIssues = append(recordIssues, fmt.Sprintf("Wildcard issuer '%s' is not recognized as a common CA", caaRecord.Value))
                status = StatusInfo
            }
            
        case "iodef":
            iodefRecordFound = true
            
            // Check if the iodef URL is valid
            if !strings.HasPrefix(caaRecord.Value, "mailto:") && !strings.HasPrefix(caaRecord.Value, "http:") && !strings.HasPrefix(caaRecord.Value, "https:") {
                recordIssues = append(recordIssues, "iodef value should be a valid mailto or http(s) URL")
                status = StatusWarning
            }
            
        default:
            recordIssues = append(recordIssues, fmt.Sprintf("Unknown CAA tag: %s", caaRecord.Tag))
            status = StatusWarning
        }
        
        // Check for critical flag (bit 128)
        if caaRecord.Flag&128 != 0 {
            recordIssues = append(recordIssues, "Critical flag is set, CAs that don't understand this record will refuse issuance")
        }
        
        records = append(records, DnsRecord{
            Host:   domain,
            Type:   CheckTypeCAAImplementation,
            Value:  fmt.Sprintf("%d %s "%s"", caaRecord.Flag, caaRecord.Tag, caaRecord.Value),
            Status: status,
            Issues: recordIssues,
        })
    }
    
    // Check for best practices
    if !issueRecordFound {
        issues = append(issues, "No 'issue' CAA records found, which should control certificate issuance")
    }
    
    if !iodefRecordFound {
        issues = append(issues, "No 'iodef' CAA record found for violation reporting")
    }
    
    if len(validIssuers) == 0 && issueRecordFound {
        issues = append(issues, "Empty CAA issue value found, this prevents all CAs from issuing certificates")
    }
    
    // Add summary record if there are issues
    if len(issues) > 0 {
        records = append(records, DnsRecord{
            Host:   domain,
            Type:   CheckTypeCAAImplementation,
            Value:  "CAA configuration issues found",
            Status: StatusWarning,
            Issues: issues,
        })
        
        *issues = append(*issues, Issue{
            Type:           StatusWarning,
            RecordType:     CheckTypeCAAImplementation,
            Description:    "CAA configuration has issues that may affect certificate issuance",
            Recommendation: "Review and update CAA records to follow best practices",
        })
    }
    
    return records, nil
}

func (c *CAAImplementationCheck) queryCAARecords(domain string) ([]*dns.CAA, error) {
    // Implementation of CAA record lookup
    // ...
    return []*dns.CAA{}, nil
}

func (c *CAAImplementationCheck) isKnownCA(issuer string) bool {
    // Strip quotes if present
    issuer = strings.Trim(issuer, """)
    
    // Remove any leading domain component separators for comparison
    issuer = strings.TrimLeft(issuer, ".")
    
    // Check for direct match
    if knownCAs[issuer] {
        return true
    }
    
    // Check if the issuer domain ends with any known CA domain
    for ca := range knownCAs {
        if strings.HasSuffix(issuer, ca) {
            return true
        }
    }
    
    return false
}

// getParentDomain returns the parent domain of the given domain
func getParentDomain(domain string) string {
    parts := strings.Split(domain, ".")
    if len(parts) <= 2 {
        return "" // No parent for TLDs or direct second-level domains
    }
    return strings.Join(parts[1:], ".")
}`})]})]}),e.jsxs("div",{className:"mb-12",children:[e.jsx("h3",{className:"text-xl font-semibold mb-4 text-blue-700",children:"TCP Fallback Testing"}),e.jsxs("div",{className:"space-y-4",children:[e.jsx("p",{className:"text-gray-700",children:"Testing proper TCP fallback behavior for large DNS responses is crucial for ensuring DNS reliability. Implement the following for TCP fallback checks:"}),e.jsx("div",{className:"bg-gray-50 p-4 rounded-md font-mono text-sm overflow-auto border border-gray-200",children:`// tcp_fallback.go

// TCPFallbackCheck implements the Check interface for TCP fallback validation
type TCPFallbackCheck struct {
    cache     Cache
    dnsClient *dns.Client
}

func NewTCPFallbackCheck(cache Cache) *TCPFallbackCheck {
    return &TCPFallbackCheck{
        cache:     cache,
        dnsClient: &dns.Client{},
    }
}

func (c *TCPFallbackCheck) Name() string {
    return "TCP Fallback"
}

func (c *TCPFallbackCheck) RecordType() RecordType {
    return CheckTypeTCPFallback
}

func (c *TCPFallbackCheck) Run(ctx context.Context, domain string, issues *[]Issue) ([]DnsRecord, error) {
    var records []DnsRecord
    
    // Get the nameservers for the domain
    nameservers, err := c.getNameservers(domain)
    if err != nil {
        return nil, err
    }
    
    if len(nameservers) == 0 {
        return []DnsRecord{{
            Host:   domain,
            Type:   CheckTypeTCPFallback,
            Value:  "No nameservers found",
            Status: StatusCritical,
            Issues: []string{"Could not identify nameservers for the domain"},
        }}, nil
    }
    
    // Test TCP connectivity to each nameserver
    var wg sync.WaitGroup
    resultChan := make(chan DnsRecord, len(nameservers))
    
    for _, ns := range nameservers {
        wg.Add(1)
        go func(nameserver string) {
            defer wg.Done()
            
            // Extract the nameserver hostname
            nameserver = strings.TrimSuffix(nameserver, ".")
            
            // Test TCP connectivity to port 53
            tcpResult := c.testTCPConnectivity(nameserver)
            
            // Test truncated response handling
            truncResult := c.testTruncatedResponse(nameserver, domain)
            
            // Combine results
            var status StatusType
            var recordIssues []string
            
            if !tcpResult.Success {
                status = StatusCritical
                recordIssues = append(recordIssues, fmt.Sprintf("TCP connection to port 53 failed: %s", tcpResult.Error))
            } else if !truncResult.Success {
                status = StatusWarning
                recordIssues = append(recordIssues, fmt.Sprintf("Failed to handle truncated DNS responses: %s", truncResult.Error))
            } else {
                status = StatusSecure
                recordIssues = append(recordIssues, "TCP fallback working correctly")
            }
            
            resultChan <- DnsRecord{
                Host:   nameserver,
                Type:   CheckTypeTCPFallback,
                Value:  fmt.Sprintf("TCP: %v, Truncation: %v", tcpResult.Success, truncResult.Success),
                Status: status,
                Issues: recordIssues,
            }
        }(ns)
    }
    
    wg.Wait()
    close(resultChan)
    
    // Collect results
    var criticalCount, warningCount int
    for result := range resultChan {
        records = append(records, result)
        
        if result.Status == StatusCritical {
            criticalCount++
        } else if result.Status == StatusWarning {
            warningCount++
        }
    }
    
    // Add summary issue if there are problems
    if criticalCount > 0 {
        *issues = append(*issues, Issue{
            Type:           StatusCritical,
            RecordType:     CheckTypeTCPFallback,
            Description:    fmt.Sprintf("%d of %d nameservers have critical TCP connectivity issues", criticalCount, len(nameservers)),
            Recommendation: "Ensure DNS servers accept TCP connections on port 53, required for handling large DNS responses",
        })
    } else if warningCount > 0 {
        *issues = append(*issues, Issue{
            Type:           StatusWarning,
            RecordType:     CheckTypeTCPFallback,
            Description:    fmt.Sprintf("%d of %d nameservers have issues handling truncated DNS responses", warningCount, len(nameservers)),
            Recommendation: "Verify proper handling of DNS message truncation and TCP fallback",
        })
    }
    
    return records, nil
}

// TCPTestResult contains the result of a TCP connectivity test
type TCPTestResult struct {
    Success bool
    Error   string
}

// testTCPConnectivity checks if a TCP connection can be established to a nameserver
func (c *TCPFallbackCheck) testTCPConnectivity(nameserver string) TCPTestResult {
    conn, err := net.DialTimeout("tcp", nameserver+":53", 5*time.Second)
    if err != nil {
        return TCPTestResult{
            Success: false,
            Error:   err.Error(),
        }
    }
    defer conn.Close()
    
    return TCPTestResult{
        Success: true,
    }
}

// testTruncatedResponse tests if the nameserver properly handles truncated DNS responses
func (c *TCPFallbackCheck) testTruncatedResponse(nameserver, domain string) TCPTestResult {
    // First try with UDP and request many records to trigger truncation
    udpClient := &dns.Client{Net: "udp"}
    
    msg := new(dns.Msg)
    msg.SetQuestion(dns.Fqdn(domain), dns.TypeANY) // ANY query often results in truncation
    msg.SetEdns0(4096, true)                       // Advertise large buffer
    
    udpResp, _, err := udpClient.Exchange(msg, nameserver+":53")
    if err != nil {
        return TCPTestResult{
            Success: false,
            Error:   fmt.Sprintf("UDP query failed: %s", err.Error()),
        }
    }
    
    // If response is truncated (TC bit set), try again with TCP
    if udpResp.Truncated {
        tcpClient := &dns.Client{Net: "tcp"}
        tcpResp, _, err := tcpClient.Exchange(msg, nameserver+":53")
        
        if err != nil {
            return TCPTestResult{
                Success: false,
                Error:   fmt.Sprintf("TCP fallback failed: %s", err.Error()),
            }
        }
        
        if tcpResp.Rcode == dns.RcodeSuccess || tcpResp.Rcode == dns.RcodeNameError {
            return TCPTestResult{
                Success: true,
            }
        }
        
        return TCPTestResult{
            Success: false,
            Error:   fmt.Sprintf("TCP fallback response had unexpected RCODE: %s", dns.RcodeToString[tcpResp.Rcode]),
        }
    }
    
    // If we can't get a truncated response, try a different approach - force TCP
    tcpClient := &dns.Client{Net: "tcp"}
    tcpResp, _, err := tcpClient.Exchange(msg, nameserver+":53")
    
    if err != nil {
        return TCPTestResult{
            Success: false,
            Error:   fmt.Sprintf("Direct TCP query failed: %s", err.Error()),
        }
    }
    
    if tcpResp.Rcode == dns.RcodeSuccess || tcpResp.Rcode == dns.RcodeNameError {
        return TCPTestResult{
            Success: true,
        }
    }
    
    return TCPTestResult{
        Success: false,
        Error:   fmt.Sprintf("Direct TCP query had unexpected RCODE: %s", dns.RcodeToString[tcpResp.Rcode]),
    }
}

// getNameservers fetches the authoritative nameservers for a domain
func (c *TCPFallbackCheck) getNameservers(domain string) ([]string, error) {
    // Implementation to get nameservers
    // ...
    return []string{}, nil
}`})]})]}),e.jsxs("div",{className:"mb-12",children:[e.jsx("h3",{className:"text-xl font-semibold mb-4 text-blue-700",children:"API Endpoints Implementation"}),e.jsxs("div",{className:"space-y-4",children:[e.jsx("p",{className:"text-gray-700",children:"The following shows the Echo-based API endpoints implementation:"}),e.jsx("div",{className:"bg-gray-50 p-4 rounded-md font-mono text-sm overflow-auto border border-gray-200",children:`// api.go

package api

import (
    "context"
    "encoding/json"
    "net/http"
    "time"
    
    "github.com/labstack/echo/v4"
    "github.com/labstack/echo/v4/middleware"
)

type API struct {
    scanner     Scanner
    resultStore ResultStore
    logger      Logger
}

type ScanRequest struct {
    Domain      string   \`json:"domain" validate:"required"\`
    RecordTypes []string \`json:"recordTypes"\`
}

// NewAPI creates a new API instance
func NewAPI(scanner Scanner, resultStore ResultStore, logger Logger) *API {
    return &API{
        scanner:     scanner,
        resultStore: resultStore,
        logger:      logger,
    }
}

// SetupRoutes configures all API routes
func SetupRoutes(e *echo.Echo, api *API) {
    // Apply common middleware
    e.Use(middleware.Recover())
    e.Use(middleware.Logger())
    e.Use(middleware.CORS())
    e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(30)))
    
    // API endpoints
    v1 := e.Group("/api/v1")
    v1.Use(middleware.KeyAuth(api.validateAPIKey))
    
    v1.GET("/scan", api.HandleGetScan)
    v1.POST("/scan", api.HandleScanDomain)
    v1.GET("/scan/:scanId", api.HandleGetScanStatus)
    v1.GET("/domain/:domain/history", api.HandleGetDomainHistory)
    v1.GET("/logs", api.HandleGetLogs)
    v1.GET("/logs/:domain", api.HandleGetDomainLogs)
    
    // Admin endpoints with additional auth
    admin := e.Group("/stats")
    admin.Use(middleware.BasicAuth(api.validateAdminAuth))
    
    admin.GET("/usage", api.HandleGetUsageStats)
    admin.GET("/performance", api.HandleGetPerformanceStats)
    admin.GET("/cache", api.HandleGetCacheStats)
    
    // Public health check endpoint
    e.GET("/health", api.HandleHealthCheck)
}

// HandleGetScan handles GET /api/v1/scan?domain=example.com&records=A,AAAA
func (a *API) HandleGetScan(c echo.Context) error {
    domain := c.QueryParam("domain")
    if domain == "" {
        return c.JSON(http.StatusBadRequest, map[string]string{
            "error": "domain parameter is required",
        })
    }
    
    recordTypes := c.QueryParam("records")
    var recordList []string
    if recordTypes != "" {
        recordList = strings.Split(recordTypes, ",")
    }
    
    // Use cached result if exists and not expired
    cachedResult, found := a.resultStore.GetLatestScan(domain)
    if found && !isResultExpired(cachedResult) {
        return c.JSON(http.StatusOK, cachedResult)
    }
    
    // Create context with timeout
    ctx, cancel := context.WithTimeout(c.Request().Context(), 30*time.Second)
    defer cancel()
    
    // Perform the scan
    result, err := a.scanner.Scan(ctx, domain, recordList)
    if err != nil {
        a.logger.Error("Scan failed", "domain", domain, "error", err)
        return c.JSON(http.StatusInternalServerError, map[string]string{
            "error": "Failed to scan domain: " + err.Error(),
        })
    }
    
    // Store the result
    a.resultStore.StoreScan(result)
    
    return c.JSON(http.StatusOK, result)
}

// HandleScanDomain handles POST /api/v1/scan for asynchronous scanning
func (a *API) HandleScanDomain(c echo.Context) error {
    var req ScanRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{
            "error": "Invalid request format: " + err.Error(),
        })
    }
    
    if req.Domain == "" {
        return c.JSON(http.StatusBadRequest, map[string]string{
            "error": "domain is required",
        })
    }
    
    // Create a scan job with unique ID
    scanID := generateScanID()
    
    // Start scan in a goroutine
    go func() {
        ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
        defer cancel()
        
        result, err := a.scanner.Scan(ctx, req.Domain, req.RecordTypes)
        if err != nil {
            a.logger.Error("Async scan failed", "domain", req.Domain, "scanID", scanID, "error", err)
            a.resultStore.StoreFailedScan(scanID, req.Domain, err.Error())
            return
        }
        
        a.resultStore.StoreScanWithID(scanID, result)
    }()
    
    return c.JSON(http.StatusAccepted, map[string]string{
        "scanId": scanID,
        "status": "pending",
    })
}

// Additional handler implementations...

// Helper functions
func isResultExpired(result ScanResult) bool {
    // Parse scan date
    scanDate, err := time.Parse(time.RFC3339, result.ScanDate)
    if err != nil {
        return true // If we can't parse the date, consider it expired
    }
    
    // Results are valid for 24 hours
    return time.Since(scanDate) > 24*time.Hour
}

func generateScanID() string {
    // Generate a unique scan ID using UUID
    return uuid.New().String()
}

func (a *API) validateAPIKey(key string, c echo.Context) (bool, error) {
    // Validate the API key
    // In production, check against database of valid keys
    return key == os.Getenv("API_KEY") || key == "test-key", nil
}

func (a *API) validateAdminAuth(username, password string, c echo.Context) (bool, error) {
    // Validate admin authentication
    return username == os.Getenv("ADMIN_USER") && password == os.Getenv("ADMIN_PASSWORD"), nil
}
`})]})]})]})}),v=()=>e.jsx("div",{className:"py-4",children:e.jsxs("div",{className:"mx-auto",children:[e.jsx("p",{className:"text-gray-700 mb-6",children:"This document provides detailed implementation instructions for each DNS security check in our system. It explains what each check is looking for, how it should be implemented, edge cases to handle, and how to evaluate the findings."}),e.jsx("section",{className:"mb-8",children:e.jsxs("div",{className:"bg-white p-6 rounded-md shadow-sm border border-gray-200 mb-8",children:[e.jsx("h2",{className:"text-xl font-bold mb-6 text-blue-600",children:"Standard DNS Record Checks"}),e.jsxs("div",{className:"space-y-8",children:[e.jsxs("div",{className:"mb-6",children:[e.jsx("h3",{className:"text-lg font-semibold text-blue-700",children:"A Records"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-2 mt-2",children:[e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Purpose:"})," Verify IPv4 address mappings"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Implementation:"})," Use ",e.jsx("code",{children:"dns.resolve4()"})," or equivalent to query A records"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Validation steps:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Verify presence of at least one A record for the domain"}),e.jsx("li",{children:"Validate each IP address is a properly formatted IPv4 address"}),e.jsx("li",{children:"Optionally check if IPs appear in known blocklists"}),e.jsx("li",{children:"Check that TTL values are reasonable (not extremely short which could indicate DNS Flux)"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Severity assessment:"})," Usually informational unless found in blocklists"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Implementation details:"})," Cache results for 300 seconds (or match TTL)"]})]})]}),e.jsxs("div",{className:"mb-6",children:[e.jsx("h3",{className:"text-lg font-semibold text-blue-700",children:"AAAA Records"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-2 mt-2",children:[e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Purpose:"})," Verify IPv6 address mappings"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Implementation:"})," Use ",e.jsx("code",{children:"dns.resolve6()"})," or equivalent to query AAAA records"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Validation steps:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Validate each IP address is a properly formatted IPv6 address"}),e.jsx("li",{children:"Not having AAAA records is common and not a security issue by itself"}),e.jsx("li",{children:"Verify network consistency with A records if both exist"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Severity assessment:"})," Informational only"]})]})]}),e.jsxs("div",{className:"mb-6",children:[e.jsx("h3",{className:"text-lg font-semibold text-blue-700",children:"MX Records"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-2 mt-2",children:[e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Purpose:"})," Verify mail server configuration"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Implementation:"})," Use ",e.jsx("code",{children:"dns.resolveMx()"})," or equivalent to query MX records"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Validation steps:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Check for presence of MX records if domain sends email"}),e.jsx("li",{children:"Verify multiple MX records exist for redundancy (at least 2 recommended)"}),e.jsx("li",{children:"Check that priority values are set correctly (lower numbers = higher priority)"}),e.jsx("li",{children:"Verify MX hostnames have valid A/AAAA records"}),e.jsx("li",{children:"Optional: Test if mail servers support STARTTLS"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Severity assessment:"})," Warning if missing MX records but SPF exists"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Edge cases:"})," Not all domains need MX records (no email services)"]})]})]}),e.jsxs("div",{className:"mb-6",children:[e.jsx("h3",{className:"text-lg font-semibold text-blue-700",children:"TXT Records"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-2 mt-2",children:[e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Purpose:"})," Examine text records for security implications"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Implementation:"})," Use ",e.jsx("code",{children:"dns.resolveTxt()"})," or equivalent to query TXT records"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Validation steps:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Parse TXT records for known security-related records (SPF, DKIM, verification tokens)"}),e.jsx("li",{children:"Check for information disclosure in TXT records (internal hostnames, paths, etc.)"}),e.jsx("li",{children:"Look for unusual or malformed records"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Severity assessment:"})," Usually informational unless sensitive data found"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Implementation note:"})," TXT records may be split into multiple strings by DNS servers, concatenate them"]})]})]}),e.jsxs("div",{className:"mb-6",children:[e.jsx("h3",{className:"text-lg font-semibold text-blue-700",children:"NS Records"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-2 mt-2",children:[e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Purpose:"})," Verify nameserver configuration and redundancy"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Implementation:"})," Use ",e.jsx("code",{children:"dns.resolveNs()"})," or equivalent to query NS records"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Validation steps:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Confirm at least 2 nameservers exist for redundancy"}),e.jsx("li",{children:"Verify nameservers are on different networks/ASNs for true redundancy"}),e.jsx("li",{children:"Check that all nameservers are responsive"}),e.jsx("li",{children:"Optionally check for consistent record sets across nameservers"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Severity assessment:"})," Warning if single nameserver, critical if none"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Implementation details:"})," Cache NS results longer (~1 hour) as they rarely change"]})]})]}),e.jsxs("div",{className:"mb-6",children:[e.jsx("h3",{className:"text-lg font-semibold text-blue-700",children:"CNAME Records"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-2 mt-2",children:[e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Purpose:"})," Check for proper canonical name aliases"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Implementation:"})," Use ",e.jsx("code",{children:"dns.resolveCname()"})," or equivalent to query CNAME records"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Validation steps:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Verify CNAME targets resolve to valid destinations"}),e.jsx("li",{children:"Check for CNAME loops or excessive CNAME chains (max 8)"}),e.jsx("li",{children:"Ensure no CNAME exists at domain apex (violation of DNS standards)"}),e.jsx("li",{children:"Look for dangling CNAMEs that could enable subdomain takeover"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Severity assessment:"})," Warning for dangling CNAMEs, info otherwise"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Edge cases:"})," Some CDNs incorrectly suggest apex CNAMEs"]})]})]}),e.jsxs("div",{className:"mb-6",children:[e.jsx("h3",{className:"text-lg font-semibold text-blue-700",children:"SPF Records"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-2 mt-2",children:[e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Purpose:"})," Validate Sender Policy Framework email authentication"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Implementation:"})," Search for ",e.jsx("code",{children:"v=spf1"})," in TXT records"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Validation steps:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Verify there is exactly one SPF record (multiple cause issues)"}),e.jsx("li",{children:"Check SPF syntax validity"}),e.jsx("li",{children:"Evaluate policy strength (-all vs ~all vs ?all vs +all)"}),e.jsx("li",{children:"Count DNS lookups (includes, redirects) - max 10 permitted"}),e.jsx("li",{children:"Test for deprecated SPF record type"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Severity assessment:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Critical: Missing SPF with DMARC record, multiple SPF records, no all directive"}),e.jsx("li",{children:"Warning: Weak policy (~all), using deprecated SPF record type"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Implementation details:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsxs("li",{children:["Use regex to parse SPF: ",e.jsx("code",{children:"/^v=spf1\\s+(.*?)$/"})]}),e.jsx("li",{children:"Count DNS lookups: +includes, +redirects, +macros, +exists"}),e.jsxs("li",{children:["Check the policy type with: ",e.jsx("code",{children:"/([-~?+])all\\b/"})]})]})]})]})]}),e.jsxs("div",{className:"mb-6",children:[e.jsx("h3",{className:"text-lg font-semibold text-blue-700",children:"DMARC Records"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-2 mt-2",children:[e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Purpose:"})," Validate Domain-based Message Authentication policy"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Implementation:"})," Query TXT record at ",e.jsx("code",{children:"_dmarc.domain.com"})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Validation steps:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsxs("li",{children:["Look for record starting with ",e.jsx("code",{children:"v=DMARC1"})]}),e.jsx("li",{children:"Check policy type (p=none vs p=quarantine vs p=reject)"}),e.jsx("li",{children:"Validate percentage setting (pct=)"}),e.jsx("li",{children:"Check reporting configuration (rua=, ruf=)"}),e.jsx("li",{children:"Validate subdomain policy (sp=) if present"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Severity assessment:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Critical: Missing DMARC when SPF and DKIM exist"}),e.jsx("li",{children:"Warning: Weak policy (p=none) or low percentage (pct=)"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Implementation details:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsxs("li",{children:["Parse DMARC into key-value pairs: ",e.jsx("code",{children:"tag1=value1; tag2=value2;"})]}),e.jsx("li",{children:"Check p= and sp= tags for policy strength"}),e.jsx("li",{children:"Verify mailto: addresses in rua= and ruf= tags"})]})]})]})]}),e.jsxs("div",{className:"mb-6",children:[e.jsx("h3",{className:"text-lg font-semibold text-blue-700",children:"DKIM Records"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-2 mt-2",children:[e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Purpose:"})," Validate DomainKeys Identified Mail cryptographic authentication"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Implementation:"})," Try common selectors at ",e.jsx("code",{children:"selector._domainkey.domain.com"})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Common selectors to try:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"default, google, k1, selector1, selector2, mail, email, dkim"}),e.jsxs("li",{children:["For Google Workspace: ",e.jsx("code",{children:"google._domainkey.domain.com"})]}),e.jsxs("li",{children:["For Microsoft: ",e.jsx("code",{children:"selector1._domainkey.domain.com"})," and ",e.jsx("code",{children:"selector2._domainkey.domain.com"})]}),e.jsxs("li",{children:["For Mailchimp: ",e.jsx("code",{children:"k1._domainkey.domain.com"})]})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Validation steps:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Verify record format (v=DKIM1; k=rsa; p=...)"}),e.jsx("li",{children:"Check key strength (minimum 1024 bits, 2048 recommended)"}),e.jsx("li",{children:"Look for testing mode flags (t=y) which should not be in production"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Severity assessment:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Warning: Weak key (1024 bits), test mode in production"}),e.jsx("li",{children:"Info: Missing DKIM (hard to definitively determine)"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Implementation details:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Key length can be estimated from the length of the p= value"}),e.jsx("li",{children:"Perform lookups in parallel with Promise.all"}),e.jsx("li",{children:"Cannot definitively determine absence since selectors are custom"})]})]})]})]})]})]})}),e.jsx("section",{className:"mb-8",children:e.jsxs("div",{className:"bg-white p-6 rounded-md shadow-sm border border-gray-200 mb-8",children:[e.jsx("h2",{className:"text-xl font-bold mb-6 text-blue-600",children:"Advanced Security Checks"}),e.jsxs("div",{className:"space-y-8",children:[e.jsxs("div",{className:"mb-6",children:[e.jsx("h3",{className:"text-lg font-semibold text-blue-700",children:"Zone Transfer Vulnerability (AXFR)"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-2 mt-2",children:[e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Purpose:"})," Detect if DNS zone transfers are allowed"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Implementation:"})," Attempt AXFR query to each nameserver"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Validation steps:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Get domain's authoritative nameservers"}),e.jsxs("li",{children:["For each nameserver, request zone transfer: ",e.jsx("code",{children:"dig @nameserver domain AXFR"})]}),e.jsx("li",{children:"Check if response contains SOA record followed by other records"}),e.jsxs("li",{children:["In Go, use ",e.jsx("code",{children:"miekg/dns"})," library with query type AXFR"]})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Severity assessment:"})," Critical if allowed, secure if denied"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Implementation details:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Use TCP for AXFR queries (required per RFC)"}),e.jsx("li",{children:"Be respectful - only attempt once per nameserver"}),e.jsx("li",{children:"Success: multiple records returned in AXFR transfer format"}),e.jsx("li",{children:'Failure: "Transfer failed", "Connection refused" or similar'})]})]})]})]}),e.jsxs("div",{className:"mb-6",children:[e.jsx("h3",{className:"text-lg font-semibold text-blue-700",children:"DNSSEC Implementation"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-2 mt-2",children:[e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Purpose:"})," Verify proper DNSSEC implementation"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Implementation:"})," Check for DNSKEY, DS records and validate chain"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Validation steps:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Query for DNSKEY records at the domain"}),e.jsx("li",{children:"Verify DS (Delegation Signer) records in parent zone"}),e.jsx("li",{children:"Check for valid RRSIG records"}),e.jsx("li",{children:"Validate signature chain from root to domain"}),e.jsx("li",{children:"Verify NSEC/NSEC3 for authenticated denial of existence"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Severity assessment:"})," Warning if DS exists but DNSKEY missing"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Implementation details:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsxs("li",{children:["Use ",e.jsx("code",{children:"dig +dnssec"})," to include DNSSEC records in response"]}),e.jsxs("li",{children:["Verify DNSKEY with ",e.jsx("code",{children:"dig +dnssec DNSKEY domain"})]}),e.jsxs("li",{children:["Check DS record with ",e.jsx("code",{children:"dig DS domain"})]}),e.jsx("li",{children:"Set DO flag (DNSSEC OK) in all queries"}),e.jsx("li",{children:"Verify AD flag (Authenticated Data) in responses"})]})]})]})]}),e.jsxs("div",{className:"mb-6",children:[e.jsx("h3",{className:"text-lg font-semibold text-blue-700",children:"DANE (DNS-based Authentication of Named Entities)"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-2 mt-2",children:[e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Purpose:"})," Verify DANE TLSA records for certificate authentication"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Implementation:"})," Check for TLSA records for common services"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Prerequisite check:"})," DNSSEC must be enabled for DANE to be effective"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Validation steps:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"First check if DNSSEC is enabled (required)"}),e.jsxs("li",{children:["Look for TLSA records at: ",e.jsx("code",{children:"_port._tcp.domain"})," for common ports:",e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"443 (HTTPS), 25 (SMTP), 587 (Submission), 465 (SMTPS)"}),e.jsx("li",{children:"993 (IMAPS), 995 (POP3S)"})]})]}),e.jsxs("li",{children:["Parse TLSA records (4 fields):",e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Certificate Usage (0-3) - Which certificate to verify against"}),e.jsx("li",{children:"Selector (0-1) - Whole cert or just public key"}),e.jsx("li",{children:"Matching Type (0-2) - Raw, SHA-256, or SHA-512"}),e.jsx("li",{children:"Certificate Association Data - Hex string of cert data"})]})]})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Certificate Usage types:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"0 (PKIX-TA): CA constraint"}),e.jsx("li",{children:"1 (PKIX-EE): Service certificate constraint"}),e.jsx("li",{children:"2 (DANE-TA): Trust anchor assertion"}),e.jsx("li",{children:"3 (DANE-EE): Domain-issued certificate"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Severity assessment:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Warning: TLSA records without DNSSEC (ineffective)"}),e.jsx("li",{children:"Secure: DNSSEC + properly formatted TLSA records"}),e.jsx("li",{children:"Info: No DANE implementation"})]})]})]})]}),e.jsxs("div",{className:"mb-6",children:[e.jsx("h3",{className:"text-lg font-semibold text-blue-700",children:"CAA Record Implementation"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-2 mt-2",children:[e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Purpose:"})," Verify proper Certificate Authority Authorization records"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Implementation:"})," Check CAA records to restrict certificate issuance"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Validation steps:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Query for CAA records (DNS record type 257)"}),e.jsxs("li",{children:["Parse CAA record format: ",e.jsx("code",{children:'flags tag "value"'})]}),e.jsxs("li",{children:["Check for three tag types:",e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsxs("li",{children:[e.jsx("code",{children:"issue"})," - Specific CAs allowed to issue certs"]}),e.jsxs("li",{children:[e.jsx("code",{children:"issuewild"})," - CAs allowed to issue wildcard certs"]}),e.jsxs("li",{children:[e.jsx("code",{children:"iodef"})," - Where to report violations"]})]})]}),e.jsx("li",{children:"Check for critical flag usage (high bit in flags field)"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Common CA identifiers:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"letsencrypt.org, digicert.com, sectigo.com, globalsign.com"}),e.jsx("li",{children:"amazon.com, pki.goog, comodo.com, entrust.net"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Severity assessment:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Warning: Malformed CAA records, critical flag with uncommon CA"}),e.jsx("li",{children:"Warning: Empty issue tag (blocks all cert issuance)"}),e.jsx("li",{children:"Info: No CAA records (optional but recommended)"}),e.jsx("li",{children:"Info: Missing iodef reporting"})]})]})]})]}),e.jsxs("div",{className:"mb-6",children:[e.jsx("h3",{className:"text-lg font-semibold text-blue-700",children:"TCP Fallback Testing"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-2 mt-2",children:[e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Purpose:"})," Verify DNS servers support TCP for large responses"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Implementation:"})," Multiple tests for TCP DNS functionality"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Validation steps:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Get authoritative nameservers for the domain"}),e.jsx("li",{children:"Test 1: Basic TCP connectivity to port 53"}),e.jsx("li",{children:"Test 2: Explicit DNS query over TCP"}),e.jsx("li",{children:"Test 3: Force a large response that requires TCP fallback"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"How to force TCP fallback:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Set small UDP buffer size (512 bytes)"}),e.jsx("li",{children:"Request multiple record types simultaneously (ANY query)"}),e.jsx("li",{children:"Look for truncation flag (TC) in response headers"}),e.jsx("li",{children:"If TC bit set, retry with TCP and verify success"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Severity assessment:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Critical: No nameservers support TCP"}),e.jsx("li",{children:"Warning: Inconsistent TCP support across nameservers"}),e.jsx("li",{children:"Secure: All nameservers support TCP properly"})]})]})]})]}),e.jsxs("div",{className:"mb-6",children:[e.jsx("h3",{className:"text-lg font-semibold text-blue-700",children:"DNS Rebinding Protection"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-2 mt-2",children:[e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Purpose:"})," Check if domain is protected against DNS rebinding attacks"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Implementation:"})," Analyze TTL values and check for rebinding protection"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Validation steps:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Check for extremely short TTL values (under 60 seconds)"}),e.jsx("li",{children:"Look for addresses in private IP ranges (rebinding target)"}),e.jsx("li",{children:"Check if records change rapidly across multiple queries"}),e.jsx("li",{children:"Search for rebinding protection headers in HTTP responses"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Private IP ranges:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"}),e.jsx("li",{children:"127.0.0.0/8, 169.254.0.0/16"}),e.jsx("li",{children:"fc00::/7 (IPv6 unique local addresses)"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Severity assessment:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Warning: Very short TTLs combined with address changes"}),e.jsx("li",{children:"Warning: Private IP addresses in public DNS"}),e.jsx("li",{children:"Secure: Normal TTL values (>300s) and consistent records"})]})]})]})]}),e.jsxs("div",{className:"mb-6",children:[e.jsx("h3",{className:"text-lg font-semibold text-blue-700",children:"DNSSEC Algorithm Strength"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-2 mt-2",children:[e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Purpose:"})," Verify strong crypto algorithms in DNSSEC"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Implementation:"})," Analyze algorithm numbers in DNSKEY records"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Algorithm reference:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"1: RSA/MD5 (deprecated, insecure)"}),e.jsx("li",{children:"3: DSA (legacy, weak)"}),e.jsx("li",{children:"5: RSA/SHA-1 (legacy, weak)"}),e.jsx("li",{children:"7: RSASHA1-NSEC3-SHA1 (legacy, weak)"}),e.jsx("li",{children:"8: RSA/SHA-256 (current, secure)"}),e.jsx("li",{children:"10: RSA/SHA-512 (current, secure)"}),e.jsx("li",{children:"13: ECDSA P-256 with SHA-256 (modern, secure)"}),e.jsx("li",{children:"14: ECDSA P-384 with SHA-384 (modern, secure)"}),e.jsx("li",{children:"15: Ed25519 (modern, secure, recommended)"}),e.jsx("li",{children:"16: Ed448 (modern, secure)"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Severity assessment:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Warning: Using deprecated algorithms (1, 3, 5, 7)"}),e.jsx("li",{children:"Warning: RSA with key length < 2048 bits"}),e.jsx("li",{children:"Secure: Modern algorithms (13-16) or RSA/SHA-256+ with =2048 bits"})]})]})]})]})]})]})}),e.jsx("section",{className:"mb-8",children:e.jsxs("div",{className:"bg-white p-6 rounded-md shadow-sm border border-gray-200 mb-8",children:[e.jsx("h2",{className:"text-xl font-bold mb-6 text-blue-600",children:"Vulnerability Checks"}),e.jsxs("div",{className:"space-y-8",children:[e.jsxs("div",{className:"mb-6",children:[e.jsx("h3",{className:"text-lg font-semibold text-blue-700",children:"Subdomain Takeover Detection"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-2 mt-2",children:[e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Purpose:"})," Identify dangling DNS records vulnerable to takeover"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Implementation:"})," Check for CNAME records pointing to abandoned services"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Validation steps:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Get all CNAME records for domain and common subdomains"}),e.jsx("li",{children:"Check if CNAME targets resolve successfully"}),e.jsxs("li",{children:["Look for known patterns of abandoned services:",e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsxs("li",{children:["GitHub Pages: ",e.jsx("code",{children:"username.github.io"})," with 404 status"]}),e.jsxs("li",{children:["Heroku: ",e.jsx("code",{children:"*.herokuapp.com"}),' with "No such app" page']}),e.jsxs("li",{children:["AWS S3: ",e.jsx("code",{children:"*.s3.amazonaws.com"}),' with "NoSuchBucket"']}),e.jsxs("li",{children:["Azure: ",e.jsx("code",{children:"*.azurewebsites.net"})," with default error page"]}),e.jsxs("li",{children:["Fastly: ",e.jsx("code",{children:"*.global.fastly.net"}),' with "Fastly error"']})]})]})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Severity assessment:"})," Critical if takeover possible"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Common vulnerable services:"})," GitHub Pages, Heroku, AWS S3, Azure, Shopify, Tumblr, Squarespace, Fastly, etc."]})]})]}),e.jsxs("div",{className:"mb-6",children:[e.jsx("h3",{className:"text-lg font-semibold text-blue-700",children:"DNS Amplification Risk"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-2 mt-2",children:[e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Purpose:"})," Check if domain can be used in DNS amplification attacks"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Implementation:"})," Test for open recursion and large response ratios"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Validation steps:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Check for open recursive DNS servers"}),e.jsxs("li",{children:["Test response size for common amplification vectors:",e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"ANY queries (often 10-100x amplification)"}),e.jsx("li",{children:"DNSSEC-signed zones (responses include signatures)"}),e.jsx("li",{children:"TXT records with large values"})]})]}),e.jsx("li",{children:"Calculate amplification factor (response size ÷ query size)"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Severity assessment:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Critical: Open recursion with high amplification (>10x)"}),e.jsx("li",{children:"Warning: Open recursion or amplification factor >4x"}),e.jsx("li",{children:"Secure: No recursion, normal response sizes"})]})]})]})]}),e.jsxs("div",{className:"mb-6",children:[e.jsx("h3",{className:"text-lg font-semibold text-blue-700",children:"DNS Server CVE Detection"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-2 mt-2",children:[e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Purpose:"})," Identify DNS servers running vulnerable software"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Implementation:"})," Fingerprint server software and check against CVE database"]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Validation steps:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsxs("li",{children:["Step 1: Identify server software and version through:",e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"DNS nameserver naming patterns (ns1.cloud-provider.com)"}),e.jsx("li",{children:'CHAOS TXT query for "version.bind" or "id.server"'}),e.jsx("li",{children:"Response header patterns (EDNS version, flags usage)"}),e.jsx("li",{children:"Behavior with malformed queries"})]})]}),e.jsxs("li",{children:["Step 2: Match identified software against CVE database:",e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"BIND: CVE-2022-2795, CVE-2021-25215, etc."}),e.jsx("li",{children:"PowerDNS: CVE-2022-37428, etc."}),e.jsx("li",{children:"Other DNS servers: Unbound, NSD, Microsoft DNS, etc."})]})]})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-semibold",children:"Severity assessment:"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1",children:[e.jsx("li",{children:"Critical: Known high-severity CVE in DNS software"}),e.jsx("li",{children:"Warning: Medium-severity vulnerabilities or outdated software"}),e.jsx("li",{children:"Secure: No known vulnerabilities, managed DNS"})]})]})]})]})]})]})}),e.jsxs("div",{className:"bg-white p-6 rounded-lg border border-gray-200 mb-8",children:[e.jsx("h3",{className:"font-semibold text-lg mb-4 text-blue-700",children:"Implementation Priority Guide"}),e.jsx("p",{className:"mb-4",children:"When implementing these checks in the Go scanner service, consider this priority order:"}),e.jsxs("ol",{className:"list-decimal pl-5 space-y-3",children:[e.jsxs("li",{children:[e.jsx("span",{className:"font-medium",children:"Essential Record Checks (High Priority)"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1 mb-2",children:[e.jsx("li",{children:"A, NS, MX Records - Basic connectivity and services"}),e.jsx("li",{children:"SPF, DMARC - Critical email security"}),e.jsx("li",{children:"Zone Transfer (AXFR) - Major vulnerability if present"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-medium",children:"Secondary Security Checks (Medium Priority)"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1 mb-2",children:[e.jsx("li",{children:"DNSSEC Implementation - Important for trust"}),e.jsx("li",{children:"CAA Records - Certificate security"}),e.jsx("li",{children:"Subdomain Takeover - Critical but less common"}),e.jsx("li",{children:"DKIM Records - Email authentication"})]})]}),e.jsxs("li",{children:[e.jsx("span",{className:"font-medium",children:"Specialized Advanced Checks (Lower Priority)"}),e.jsxs("ul",{className:"list-disc pl-5 mt-1 mb-2",children:[e.jsx("li",{children:"DANE, TCP Fallback, DNS Algorithm Strength"}),e.jsx("li",{children:"NSEC3 Parameters, DNS Cookies"}),e.jsx("li",{children:"DNS Rebinding Protection"})]})]})]}),e.jsxs("div",{className:"mt-5 p-4 bg-blue-50 rounded-md border border-blue-200",children:[e.jsx("h4",{className:"font-semibold mb-2",children:"Performance Optimization Tips"}),e.jsxs("ul",{className:"list-disc pl-5 space-y-1",children:[e.jsx("li",{children:"Implement parallel execution with goroutines for all checks"}),e.jsx("li",{children:"Use context cancellation to terminate long-running checks"}),e.jsx("li",{children:"Optimize cache key generation for maximum hit rate"}),e.jsx("li",{children:"Use tiered caching with in-memory first, then Redis for scale"}),e.jsx("li",{children:"Add circuit breakers for unreliable external nameservers"})]})]})]})]})}),c=[{id:"api-endpoints",title:"API Endpoints"},{id:"dns-checks-overview",title:"DNS Checks Overview"},{id:"implementation-guide",title:"Detailed Implementation Guide"},{id:"go-implementation",title:"Go Implementation Guidelines"}],k=()=>{const u=l.useRef(null),[h,x]=l.useState("api-endpoints");l.useEffect(()=>{const t=new IntersectionObserver(a=>{a.forEach(n=>{n.isIntersecting&&x(n.target.id)})},{threshold:.2,rootMargin:"-100px 0px -60% 0px"});return c.forEach(({id:a})=>{const n=document.getElementById(a);n&&t.observe(n)}),()=>{c.forEach(({id:a})=>{const n=document.getElementById(a);n&&t.unobserve(n)})}},[]);const p=t=>{const a=document.getElementById(t);a&&a.scrollIntoView({behavior:"smooth"})};return e.jsx("main",{className:"flex-grow pt-8",children:e.jsxs("div",{className:"container mx-auto px-4 mb-20",children:[e.jsx("h1",{className:"text-3xl font-bold mb-6",children:"API Documentation"}),e.jsxs("div",{className:"flex gap-8",children:[e.jsx("aside",{className:"hidden lg:block w-[220px] flex-shrink-0",children:e.jsx("div",{className:"sticky top-24",children:e.jsxs("div",{className:"bg-gray-50 rounded-lg p-4",children:[e.jsx("h3",{className:"text-sm font-semibold text-gray-900 mb-4",children:"Contents"}),e.jsx("nav",{className:"space-y-3",children:c.map(t=>e.jsxs("button",{onClick:()=>p(t.id),className:`block text-sm transition-colors text-left flex items-start gap-2 group w-full ${h===t.id?"font-bold text-gray-900":"text-gray-700 hover:text-gray-900"}`,children:[e.jsx("span",{className:"flex-shrink-0 w-1.5 h-1.5 rounded-full mt-1.5 group-hover:scale-125 transition-transform bg-indigo-500"}),e.jsx("span",{className:"hover:underline",children:t.title})]},t.id))})]})})}),e.jsxs("div",{className:"flex-1 max-w-4xl",ref:u,children:[e.jsxs("div",{className:"lg:hidden mb-6 bg-gray-50 rounded-lg p-4",children:[e.jsx("h3",{className:"text-sm font-semibold text-gray-900 mb-4",children:"Contents"}),e.jsx("nav",{className:"space-y-3",children:c.map(t=>e.jsxs("button",{onClick:()=>p(t.id),className:`block text-sm transition-colors text-left flex items-start gap-2 group ${h===t.id?"font-bold text-gray-900":"text-gray-700 hover:text-gray-900"}`,children:[e.jsx("span",{className:"flex-shrink-0 w-1.5 h-1.5 rounded-full mt-1.5 group-hover:scale-125 transition-transform bg-indigo-500"}),e.jsx("span",{className:"hover:underline",children:t.title})]},t.id))})]}),e.jsxs("section",{id:"api-endpoints",className:"mb-16 scroll-mt-24",children:[e.jsx("h2",{className:"text-2xl font-bold mb-4 pb-2 border-b border-gray-200",children:"API Endpoints"}),e.jsx(N,{})]}),e.jsxs("section",{id:"dns-checks-overview",className:"mb-16 scroll-mt-24",children:[e.jsx("h2",{className:"text-2xl font-bold mb-4 pb-2 border-b border-gray-200",children:"DNS Checks Overview"}),e.jsx(b,{})]}),e.jsxs("section",{id:"implementation-guide",className:"mb-16 scroll-mt-24",children:[e.jsx("h2",{className:"text-2xl font-bold mb-4 pb-2 border-b border-gray-200",children:"Detailed Implementation Guide"}),e.jsx(v,{})]}),e.jsxs("section",{id:"go-implementation",className:"mb-16 scroll-mt-24",children:[e.jsx("h2",{className:"text-2xl font-bold mb-4 pb-2 border-b border-gray-200",children:"Go Implementation Guidelines"}),e.jsx(S,{})]})]})]})]})})};export{k as default};

