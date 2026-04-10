import{r as l,g as c,j as e,L as i}from"./index-CFKu6LhM.js";import{B as m}from"./Breadcrumbs-vmUX-SxX.js";const a=[{id:"getting-started",title:"Getting Started"},{id:"authentication",title:"Authentication"},{id:"base-url",title:"Base URL"},{id:"domain-scan",title:"Domain Scan"},{id:"json-export",title:"JSON Export"},{id:"scan-history",title:"Scan History"},{id:"rate-limits",title:"Rate Limits"},{id:"error-responses",title:"Error Responses"},{id:"code-examples",title:"Code Examples"},{id:"troubleshooting",title:"Troubleshooting"}],p=()=>{const[o,n]=l.useState("getting-started");c({title:"API Documentation - DNSAudit.io",description:"Complete API reference for DNSAudit.io DNS security scanning. Learn how to integrate DNS security scans into your applications and workflows.",keywords:"DNS API, security scanning API, DNS audit API, domain security API, DNSSEC API",canonical:"https://dnsaudit.io/docs/api"}),l.useEffect(()=>{const s=new IntersectionObserver(t=>{t.forEach(r=>{r.isIntersecting&&n(r.target.id)})},{threshold:.2,rootMargin:"-100px 0px -60% 0px"});return a.forEach(({id:t})=>{const r=document.getElementById(t);r&&s.observe(r)}),()=>{a.forEach(({id:t})=>{const r=document.getElementById(t);r&&s.unobserve(r)})}},[]);const d=s=>{const t=document.getElementById(s);t&&t.scrollIntoView({behavior:"smooth"})};return e.jsxs("div",{className:"min-h-screen bg-white",children:[e.jsx("div",{className:"bg-white",children:e.jsx("div",{className:"max-w-6xl mx-auto px-4 py-6",children:e.jsx(m,{items:[{label:"Home",href:"/"},{label:"Documentation",href:"/docs"},{label:"API Reference",href:""}]})})}),e.jsxs("div",{className:"max-w-6xl mx-auto px-4 py-8",children:[e.jsxs("div",{className:"mb-8",children:[e.jsx("h1",{className:"text-3xl font-bold text-gray-900 mb-2",children:"API Reference"}),e.jsx("p",{className:"text-gray-600",children:"Integrate DNS security scanning into your applications"})]}),e.jsxs("div",{className:"flex gap-8",children:[e.jsx("aside",{className:"hidden lg:block w-[220px] flex-shrink-0",children:e.jsx("div",{className:"sticky top-28 pt-4 max-h-[calc(100vh-10rem)] overflow-y-auto",children:e.jsxs("div",{className:"bg-gray-50 rounded-lg p-4",children:[e.jsx("h3",{className:"text-sm font-semibold text-gray-900 mb-4",children:"Table of Contents"}),e.jsx("nav",{className:"space-y-3",children:a.map(s=>e.jsxs("button",{onClick:()=>d(s.id),className:`block text-sm transition-colors text-left flex items-start gap-2 group w-full ${o===s.id?"font-bold text-gray-900":"text-gray-700 hover:text-gray-900"}`,children:[e.jsx("span",{className:"flex-shrink-0 w-1.5 h-1.5 rounded-full mt-1.5 group-hover:scale-125 transition-transform",style:{backgroundColor:"#FE6A05"}}),e.jsx("span",{className:"hover:underline",children:s.title})]},s.id))})]})})}),e.jsxs("div",{className:"flex-1 pt-4 min-w-0 overflow-hidden",children:[e.jsxs("div",{className:"bg-[#EEF2FF] border border-indigo-200 rounded-lg p-6 mb-8",children:[e.jsx("h2",{className:"text-lg font-semibold text-indigo-900 mb-2",children:"API Access"}),e.jsxs("p",{className:"text-indigo-800",children:["API access is available for registered users with API permissions enabled by our team.",e.jsx("br",{}),e.jsx(i,{href:"/contact",className:"text-indigo-600 hover:text-indigo-700 underline",children:"Contact us"})," if you need programmatic access to DNS security scanning."]})]}),e.jsxs("div",{className:"lg:hidden mb-8 bg-gray-50 rounded-lg p-4",children:[e.jsx("h3",{className:"text-sm font-semibold text-gray-900 mb-4",children:"Table of Contents"}),e.jsx("nav",{className:"space-y-3",children:a.map(s=>e.jsxs("button",{onClick:()=>d(s.id),className:`block text-sm transition-colors text-left flex items-start gap-2 group ${o===s.id?"font-bold text-gray-900":"text-gray-700 hover:text-gray-900"}`,children:[e.jsx("span",{className:"flex-shrink-0 w-1.5 h-1.5 rounded-full mt-1.5 group-hover:scale-125 transition-transform",style:{backgroundColor:"#FE6A05"}}),e.jsx("span",{className:"hover:underline",children:s.title})]},s.id))})]}),e.jsxs("div",{className:"prose max-w-none text-gray-700",children:[e.jsx("h2",{id:"getting-started",className:"text-2xl font-semibold text-gray-900 mb-4",children:"Getting Started"}),e.jsx("p",{className:"mb-4",children:"The DNSAudit.io API lets you run DNS security scans programmatically. You can scan domains, retrieve detailed results, export PDF reports, and get summary data for your domains. All endpoints return JSON by default, with XML available as an alternative format."}),e.jsx("p",{className:"mb-6",children:"Every API request requires authentication using your API key. Include your key in the request header as shown in the examples below."}),e.jsx("h2",{id:"authentication",className:"text-2xl font-semibold text-gray-900 mb-4",children:"Authentication"}),e.jsxs("p",{className:"mb-4",children:["Pass your API key in the ",e.jsx("code",{className:"bg-gray-100 px-2 py-0.5 rounded text-sm",children:"X-API-Key"})," header with every request. Your key is available in your dashboard under API Settings once access has been enabled."]}),e.jsx("pre",{className:"bg-gray-100 text-gray-800 p-4 rounded-md mb-6 overflow-x-auto text-sm",children:e.jsx("code",{children:`curl -H "X-API-Key: your-api-key" \\
  https://dnsaudit.io/api/v1/scan?domain=example.com`})}),e.jsx("h2",{id:"base-url",className:"text-2xl font-semibold text-gray-900 mb-4",children:"Base URL"}),e.jsx("p",{className:"mb-6",children:"All API endpoints are served from:"}),e.jsx("pre",{className:"bg-gray-100 text-gray-800 p-4 rounded-md mb-8 overflow-x-auto text-sm",children:e.jsx("code",{children:"https://dnsaudit.io/api"})}),e.jsxs("div",{className:"border-t border-gray-200 pt-8 mb-8",children:[e.jsx("h2",{id:"domain-scan",className:"text-2xl font-semibold text-gray-900 mb-4",children:"Domain Scan"}),e.jsx("p",{className:"mb-4",children:"Run a complete DNS security scan on any domain. This performs over 26 security checks including DNSSEC validation, email authentication (SPF, DKIM, DMARC), zone transfer tests, and vulnerability detection."}),e.jsx("h3",{className:"text-xl font-semibold text-gray-900 mb-3",children:"Endpoint"}),e.jsx("pre",{className:"bg-gray-100 text-gray-800 p-4 rounded-md mb-4 overflow-x-auto text-sm",children:e.jsx("code",{children:"GET /v1/scan?domain=example.com"})}),e.jsx("h3",{className:"text-xl font-semibold text-gray-900 mb-3",children:"Parameters"}),e.jsx("div",{className:"bg-gray-50 rounded-lg p-4 mb-4",children:e.jsxs("table",{className:"w-full text-sm",children:[e.jsx("thead",{children:e.jsxs("tr",{className:"border-b border-gray-200",children:[e.jsx("th",{className:"text-left py-2 font-semibold text-gray-900",children:"Parameter"}),e.jsx("th",{className:"text-left py-2 font-semibold text-gray-900",children:"Type"}),e.jsx("th",{className:"text-left py-2 font-semibold text-gray-900",children:"Required"}),e.jsx("th",{className:"text-left py-2 font-semibold text-gray-900",children:"Description"})]})}),e.jsxs("tbody",{children:[e.jsxs("tr",{className:"border-b border-gray-100",children:[e.jsx("td",{className:"py-2",children:e.jsx("code",{className:"bg-gray-200 px-1.5 py-0.5 rounded text-xs",children:"domain"})}),e.jsx("td",{className:"py-2",children:"string"}),e.jsx("td",{className:"py-2",children:"Yes"}),e.jsx("td",{className:"py-2",children:"The domain to scan (e.g., example.com)"})]}),e.jsxs("tr",{children:[e.jsx("td",{className:"py-2",children:e.jsx("code",{className:"bg-gray-200 px-1.5 py-0.5 rounded text-xs",children:"format"})}),e.jsx("td",{className:"py-2",children:"string"}),e.jsx("td",{className:"py-2",children:"No"}),e.jsxs("td",{className:"py-2",children:["Response format: ",e.jsx("code",{className:"bg-gray-200 px-1 rounded text-xs",children:"json"})," (default) or ",e.jsx("code",{className:"bg-gray-200 px-1 rounded text-xs",children:"xml"})]})]})]})]})}),e.jsx("h3",{className:"text-xl font-semibold text-gray-900 mb-3",children:"Example Request"}),e.jsx("pre",{className:"bg-gray-100 text-gray-800 p-4 rounded-md mb-4 overflow-x-auto text-sm",children:e.jsx("code",{children:`curl -X GET "https://dnsaudit.io/api/v1/scan?domain=example.com" \\
  -H "X-API-Key: your-api-key"`})}),e.jsx("h3",{className:"text-xl font-semibold text-gray-900 mb-3",children:"Example Response"}),e.jsx("pre",{className:"bg-gray-100 text-gray-800 p-4 rounded-md mb-6 overflow-x-auto text-sm",children:e.jsx("code",{children:`{
  "status": "complete",
  "domain": "example.com",
  "scanDate": "2025-01-15T14:30:00.000Z",
  "securityScore": 85,
  "grade": "B+",
  "summary": {
    "criticalIssues": 0,
    "warnings": 3,
    "passed": 23
  },
  "results": {
    "spf": {
      "status": "pass",
      "record": "v=spf1 include:_spf.google.com ~all",
      "details": "Valid SPF record found"
    },
    "dmarc": {
      "status": "warning",
      "record": "v=DMARC1; p=none",
      "details": "DMARC policy set to none - consider quarantine or reject"
    },
    "dnssec": {
      "status": "pass",
      "details": "DNSSEC is properly configured"
    }
    // ... additional check results
  }
}`})})]}),e.jsxs("div",{className:"border-t border-gray-200 pt-8 mb-8",children:[e.jsx("h2",{id:"json-export",className:"text-2xl font-semibold text-gray-900 mb-4",children:"JSON Export"}),e.jsx("p",{className:"mb-4",children:"Retrieve the full scan results as structured JSON data. Useful for integrating scan results into your own dashboards, monitoring systems, or compliance reports."}),e.jsx("h3",{className:"text-xl font-semibold text-gray-900 mb-3",children:"Endpoint"}),e.jsx("pre",{className:"bg-gray-100 text-gray-800 p-4 rounded-md mb-4 overflow-x-auto text-sm",children:e.jsx("code",{children:"GET /export/json/:domain"})}),e.jsx("h3",{className:"text-xl font-semibold text-gray-900 mb-3",children:"Example Request"}),e.jsx("pre",{className:"bg-gray-100 text-gray-800 p-4 rounded-md mb-4 overflow-x-auto text-sm",children:e.jsx("code",{children:`curl -X GET "https://dnsaudit.io/api/export/json/example.com" \\
  -H "X-API-Key: your-api-key"`})}),e.jsx("h3",{className:"text-xl font-semibold text-gray-900 mb-3",children:"Example Response"}),e.jsx("pre",{className:"bg-gray-100 text-gray-800 p-4 rounded-md mb-6 overflow-x-auto text-sm",children:e.jsx("code",{children:`{
  "domain": "example.com",
  "scanDate": "2025-01-15T14:30:00.000Z",
  "securityScore": 85,
  "grade": "B+",
  "results": {
    // Complete scan results object
  }
}`})})]}),e.jsxs("div",{className:"border-t border-gray-200 pt-8 mb-8",children:[e.jsx("h2",{id:"scan-history",className:"text-2xl font-semibold text-gray-900 mb-4",children:"Scan History"}),e.jsx("p",{className:"mb-4",children:"Retrieve your recent scan history. This endpoint returns a list of domains you have scanned along with their scores and scan dates."}),e.jsx("h3",{className:"text-xl font-semibold text-gray-900 mb-3",children:"Endpoint"}),e.jsx("pre",{className:"bg-gray-100 text-gray-800 p-4 rounded-md mb-4 overflow-x-auto text-sm",children:e.jsx("code",{children:"GET /v1/scan-history"})}),e.jsx("h3",{className:"text-xl font-semibold text-gray-900 mb-3",children:"Parameters"}),e.jsx("div",{className:"bg-gray-50 rounded-lg p-4 mb-4",children:e.jsxs("table",{className:"w-full text-sm",children:[e.jsx("thead",{children:e.jsxs("tr",{className:"border-b border-gray-200",children:[e.jsx("th",{className:"text-left py-2 font-semibold text-gray-900",children:"Parameter"}),e.jsx("th",{className:"text-left py-2 font-semibold text-gray-900",children:"Type"}),e.jsx("th",{className:"text-left py-2 font-semibold text-gray-900",children:"Required"}),e.jsx("th",{className:"text-left py-2 font-semibold text-gray-900",children:"Description"})]})}),e.jsx("tbody",{children:e.jsxs("tr",{children:[e.jsx("td",{className:"py-2",children:e.jsx("code",{className:"bg-gray-200 px-1.5 py-0.5 rounded text-xs",children:"limit"})}),e.jsx("td",{className:"py-2",children:"integer"}),e.jsx("td",{className:"py-2",children:"No"}),e.jsx("td",{className:"py-2",children:"Number of results to return (default: 10, max: 100)"})]})})]})}),e.jsx("h3",{className:"text-xl font-semibold text-gray-900 mb-3",children:"Example Request"}),e.jsx("pre",{className:"bg-gray-100 text-gray-800 p-4 rounded-md mb-4 overflow-x-auto text-sm",children:e.jsx("code",{children:`curl -X GET "https://dnsaudit.io/api/v1/scan-history?limit=20" \\
  -H "X-API-Key: your-api-key"`})}),e.jsx("h3",{className:"text-xl font-semibold text-gray-900 mb-3",children:"Example Response"}),e.jsx("pre",{className:"bg-gray-100 text-gray-800 p-4 rounded-md mb-6 overflow-x-auto text-sm",children:e.jsx("code",{children:`{
  "scans": [
    {
      "domain": "example.com",
      "scanDate": "2025-01-15T14:30:00.000Z",
      "securityScore": 85,
      "grade": "B+"
    },
    {
      "domain": "mysite.org",
      "scanDate": "2025-01-14T10:15:00.000Z",
      "securityScore": 92,
      "grade": "A"
    }
  ],
  "total": 42
}`})})]}),e.jsxs("div",{className:"border-t border-gray-200 pt-8 mb-8",children:[e.jsx("h2",{id:"rate-limits",className:"text-2xl font-semibold text-gray-900 mb-4",children:"Rate Limits"}),e.jsx("p",{className:"mb-4",children:"API requests are subject to rate limiting to ensure fair usage and prevent abuse. The following limits apply:"}),e.jsx("div",{className:"bg-gray-50 rounded-lg p-4 mb-6",children:e.jsxs("table",{className:"w-full text-sm",children:[e.jsx("thead",{children:e.jsxs("tr",{className:"border-b border-gray-200",children:[e.jsx("th",{className:"text-left py-2 font-semibold text-gray-900",children:"Limit Type"}),e.jsx("th",{className:"text-left py-2 font-semibold text-gray-900",children:"Value"}),e.jsx("th",{className:"text-left py-2 font-semibold text-gray-900",children:"Description"})]})}),e.jsxs("tbody",{children:[e.jsxs("tr",{className:"border-b border-gray-100",children:[e.jsx("td",{className:"py-2 font-medium",children:"Daily Scan Limit"}),e.jsx("td",{className:"py-2",children:"20 scans/day"}),e.jsx("td",{className:"py-2",children:"Maximum scans per account per day (resets at midnight UTC)"})]}),e.jsxs("tr",{className:"border-b border-gray-100",children:[e.jsx("td",{className:"py-2 font-medium",children:"Burst Limit"}),e.jsx("td",{className:"py-2",children:"10 requests/minute"}),e.jsx("td",{className:"py-2",children:"Maximum requests per API key within a 1-minute window"})]})]})]})}),e.jsx("h3",{className:"text-xl font-semibold text-gray-900 mb-3",children:"429 Rate Limit Response"}),e.jsxs("p",{className:"mb-4",children:["When you exceed a rate limit, the API returns a ",e.jsx("code",{className:"bg-gray-100 px-2 py-0.5 rounded text-sm",children:"429 Too Many Requests"})," response with details about the limit exceeded."]}),e.jsx("h4",{className:"text-lg font-semibold text-gray-900 mb-2",children:"Daily Limit Exceeded"}),e.jsx("pre",{className:"bg-gray-100 text-gray-800 p-4 rounded-md mb-4 overflow-x-auto text-sm",children:e.jsx("code",{children:`{
  "error": "Rate limit exceeded",
  "message": "You've reached your daily scan limit (20 scans). To help prevent abuse, we limit scans per account. Your limit will reset in 24 hours.",
  "limit": 20,
  "remaining": 0,
  "resetDate": "2025-01-16"
}`})}),e.jsx("h4",{className:"text-lg font-semibold text-gray-900 mb-2",children:"Burst Limit Exceeded"}),e.jsx("pre",{className:"bg-gray-100 text-gray-800 p-4 rounded-md mb-6 overflow-x-auto text-sm",children:e.jsx("code",{children:`{
  "error": "Rate limit exceeded",
  "message": "Too many requests. Please wait 45 seconds before trying again.",
  "retryAfter": 45
}`})}),e.jsx("p",{className:"mb-6 text-gray-600",children:"When you receive a 429 response, wait for the specified time before retrying. For burst limits, this is typically under a minute. For daily limits, wait until the next day (midnight UTC)."})]}),e.jsxs("div",{className:"border-t border-gray-200 pt-8 mb-8",children:[e.jsx("h2",{id:"error-responses",className:"text-2xl font-semibold text-gray-900 mb-4",children:"Error Responses"}),e.jsx("p",{className:"mb-4",children:"The API uses standard HTTP status codes. Here are the common error responses:"}),e.jsx("div",{className:"bg-gray-50 rounded-lg p-4 mb-6",children:e.jsxs("table",{className:"w-full text-sm",children:[e.jsx("thead",{children:e.jsxs("tr",{className:"border-b border-gray-200",children:[e.jsx("th",{className:"text-left py-2 font-semibold text-gray-900",children:"Status"}),e.jsx("th",{className:"text-left py-2 font-semibold text-gray-900",children:"Meaning"})]})}),e.jsxs("tbody",{children:[e.jsxs("tr",{className:"border-b border-gray-100",children:[e.jsx("td",{className:"py-2",children:e.jsx("code",{className:"bg-gray-200 px-1.5 py-0.5 rounded text-xs",children:"400"})}),e.jsx("td",{className:"py-2",children:"Bad Request - Invalid domain format or missing required parameters"})]}),e.jsxs("tr",{className:"border-b border-gray-100",children:[e.jsx("td",{className:"py-2",children:e.jsx("code",{className:"bg-gray-200 px-1.5 py-0.5 rounded text-xs",children:"401"})}),e.jsx("td",{className:"py-2",children:"Unauthorized - Missing or invalid API key"})]}),e.jsxs("tr",{className:"border-b border-gray-100",children:[e.jsx("td",{className:"py-2",children:e.jsx("code",{className:"bg-gray-200 px-1.5 py-0.5 rounded text-xs",children:"403"})}),e.jsx("td",{className:"py-2",children:"Forbidden - API access not enabled for your account"})]}),e.jsxs("tr",{className:"border-b border-gray-100",children:[e.jsx("td",{className:"py-2",children:e.jsx("code",{className:"bg-gray-200 px-1.5 py-0.5 rounded text-xs",children:"404"})}),e.jsx("td",{className:"py-2",children:"Not Found - No scan results found for the specified domain"})]}),e.jsxs("tr",{className:"border-b border-gray-100",children:[e.jsx("td",{className:"py-2",children:e.jsx("code",{className:"bg-gray-200 px-1.5 py-0.5 rounded text-xs",children:"429"})}),e.jsxs("td",{className:"py-2",children:["Too Many Requests - Daily limit or burst limit exceeded (see ",e.jsx("a",{href:"#rate-limits",className:"text-indigo-600 hover:text-indigo-700 underline",children:"Rate Limits"}),")"]})]}),e.jsxs("tr",{children:[e.jsx("td",{className:"py-2",children:e.jsx("code",{className:"bg-gray-200 px-1.5 py-0.5 rounded text-xs",children:"500"})}),e.jsx("td",{className:"py-2",children:"Internal Server Error - Something went wrong on our end"})]})]})]})}),e.jsx("h3",{className:"text-xl font-semibold text-gray-900 mb-3",children:"Error Response Format"}),e.jsx("pre",{className:"bg-gray-100 text-gray-800 p-4 rounded-md mb-6 overflow-x-auto text-sm",children:e.jsx("code",{children:`{
  "error": "Invalid domain format",
  "code": "INVALID_DOMAIN"
}`})})]}),e.jsxs("div",{className:"border-t border-gray-200 pt-8",children:[e.jsx("h2",{id:"code-examples",className:"text-2xl font-semibold text-gray-900 mb-4",children:"Code Examples"}),e.jsx("h3",{className:"text-xl font-semibold text-gray-900 mb-3",children:"Python"}),e.jsx("pre",{className:"bg-gray-100 text-gray-800 p-4 rounded-md mb-6 overflow-x-auto text-sm",children:e.jsx("code",{children:`import requests

API_KEY = "your-api-key"
BASE_URL = "https://dnsaudit.io/api"

def scan_domain(domain):
    response = requests.get(
        f"{BASE_URL}/v1/scan",
        params={"domain": domain},
        headers={"X-API-Key": API_KEY}
    )
    response.raise_for_status()
    return response.json()

def download_pdf_report(domain, output_path):
    response = requests.get(
        f"{BASE_URL}/export/pdf/{domain}",
        params={"format": "detailed"},
        headers={"X-API-Key": API_KEY}
    )
    response.raise_for_status()
    with open(output_path, "wb") as f:
        f.write(response.content)

# Run a scan
result = scan_domain("example.com")
print(f"Score: {result['securityScore']}, Grade: {result['grade']}")

# Download report
download_pdf_report("example.com", "security-report.pdf")`})}),e.jsx("h3",{className:"text-xl font-semibold text-gray-900 mb-3",children:"JavaScript (Node.js)"}),e.jsx("pre",{className:"bg-gray-100 text-gray-800 p-4 rounded-md mb-6 overflow-x-auto text-sm",children:e.jsx("code",{children:`const API_KEY = "your-api-key";
const BASE_URL = "https://dnsaudit.io/api";

async function scanDomain(domain) {
  const response = await fetch(
    \`\${BASE_URL}/v1/scan?domain=\${encodeURIComponent(domain)}\`,
    {
      headers: { "X-API-Key": API_KEY }
    }
  );
  
  if (!response.ok) {
    throw new Error(\`Scan failed: \${response.status}\`);
  }
  
  return response.json();
}

async function downloadPdfReport(domain) {
  const response = await fetch(
    \`\${BASE_URL}/export/pdf/\${domain}?format=detailed\`,
    {
      headers: { "X-API-Key": API_KEY }
    }
  );
  
  if (!response.ok) {
    throw new Error(\`PDF export failed: \${response.status}\`);
  }
  
  return response.arrayBuffer();
}

// Usage
scanDomain("example.com")
  .then(result => {
    console.log(\`Score: \${result.securityScore}, Grade: \${result.grade}\`);
  })
  .catch(console.error);`})}),e.jsx("h3",{className:"text-xl font-semibold text-gray-900 mb-3",children:"cURL (Bash Script)"}),e.jsx("pre",{className:"bg-gray-100 text-gray-800 p-4 rounded-md mb-6 overflow-x-auto text-sm",children:e.jsx("code",{children:`#!/bin/bash

API_KEY="your-api-key"
DOMAIN="example.com"

# Run scan and save results
curl -s -H "X-API-Key: $API_KEY" \\
  "https://dnsaudit.io/api/v1/scan?domain=$DOMAIN" | jq .

# Download PDF report
curl -s -H "X-API-Key: $API_KEY" \\
  "https://dnsaudit.io/api/export/pdf/$DOMAIN" \\
  -o "$DOMAIN-report.pdf"

echo "Report saved to $DOMAIN-report.pdf"`})}),e.jsx("h3",{className:"text-xl font-semibold text-gray-900 mb-3",children:"PHP"}),e.jsx("pre",{className:"bg-gray-100 text-gray-800 p-4 rounded-md mb-6 overflow-x-auto text-sm",children:e.jsx("code",{children:`<?php

$apiKey = "your-api-key";
$baseUrl = "https://dnsaudit.io/api";

function scanDomain($domain) {
    global $apiKey, $baseUrl;
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $baseUrl . "/v1/scan?domain=" . urlencode($domain));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "X-API-Key: " . $apiKey
    ]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode !== 200) {
        throw new Exception("Scan failed with status: " . $httpCode);
    }
    
    return json_decode($response, true);
}

function downloadPdfReport($domain, $outputPath) {
    global $apiKey, $baseUrl;
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $baseUrl . "/export/pdf/" . urlencode($domain) . "?format=detailed");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "X-API-Key: " . $apiKey
    ]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode !== 200) {
        throw new Exception("PDF export failed with status: " . $httpCode);
    }
    
    file_put_contents($outputPath, $response);
}

// Run a scan
$result = scanDomain("example.com");
echo "Score: " . $result['securityScore'] . ", Grade: " . $result['grade'] . "\\n";

// Download report
downloadPdfReport("example.com", "security-report.pdf");`})})]}),e.jsxs("div",{className:"border-t border-gray-200 pt-8 mb-8",children:[e.jsx("h2",{id:"troubleshooting",className:"text-2xl font-semibold text-gray-900 mb-4",children:"Troubleshooting"}),e.jsxs("div",{className:"space-y-4",children:[e.jsxs("div",{children:[e.jsx("h3",{className:"text-lg font-medium text-gray-900 mb-2",children:"401 Unauthorized"}),e.jsxs("p",{children:["Your API key is missing, invalid, or has been revoked. Check that you're including the ",e.jsx("code",{className:"bg-gray-100 px-2 py-0.5 rounded text-sm",children:"X-API-Key"})," header and that your key is correct."]})]}),e.jsxs("div",{children:[e.jsx("h3",{className:"text-lg font-medium text-gray-900 mb-2",children:"403 Forbidden"}),e.jsx("p",{children:"Your account doesn't have permission for this endpoint. API access must be enabled by our team."})]}),e.jsxs("div",{children:[e.jsx("h3",{className:"text-lg font-medium text-gray-900 mb-2",children:"429 Too Many Requests"}),e.jsxs("p",{children:["You've exceeded the rate limit. Wait a few seconds before retrying. See the ",e.jsx("a",{href:"#rate-limits",className:"text-[#6366F1] hover:underline",children:"Rate Limits"})," section for details."]})]}),e.jsxs("div",{children:[e.jsx("h3",{className:"text-lg font-medium text-gray-900 mb-2",children:"Need Help?"}),e.jsxs("p",{children:["If you're having issues with your API key or need access enabled, ",e.jsx(i,{href:"/contact",className:"text-[#6366F1] hover:underline",children:"contact us"})," and we'll help you out."]})]})]})]})]})]})]})]})]})};export{p as default};

