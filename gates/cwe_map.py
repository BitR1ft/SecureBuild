"""SecureBuild CI/CD Security Gate - CWE ID Mapping"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class CWEInfo:
    """Detailed information about a CWE entry."""

    cwe_id: str
    name: str
    description: str
    severity_hint: str = "medium"
    category: str = ""


# Maps CWE IDs to detailed information. This is the authoritative
# lookup table for all CWE classifications used in SecureBuild.

CWE_DATABASE: Dict[str, CWEInfo] = {
    "CWE-89": CWEInfo(
        cwe_id="CWE-89",
        name="SQL Injection",
        description="The software constructs all or part of an SQL command "
                    "using externally-influenced input from an upstream component, "
                    "but it does not neutralize or incorrectly neutralizes special "
                    "elements that could modify the intended SQL command.",
        severity_hint="high",
        category="injection",
    ),
    "CWE-78": CWEInfo(
        cwe_id="CWE-78",
        name="OS Command Injection",
        description="The software constructs all or part of an OS command "
                    "using externally-influenced input from an upstream component, "
                    "but it does not neutralize or incorrectly neutralizes special "
                    "elements that could modify the intended OS command.",
        severity_hint="critical",
        category="injection",
    ),
    "CWE-79": CWEInfo(
        cwe_id="CWE-79",
        name="Cross-site Scripting (XSS)",
        description="The software does not neutralize or incorrectly neutralizes "
                    "user-controlled input before it is placed in output that is "
                    "used as a web page that is served to other users.",
        severity_hint="high",
        category="injection",
    ),
    "CWE-94": CWEInfo(
        cwe_id="CWE-94",
        name="Code Injection",
        description="The software allows user input to control or influence "
                    "code that is executed at runtime.",
        severity_hint="critical",
        category="injection",
    ),
    "CWE-95": CWEInfo(
        cwe_id="CWE-95",
        name="Eval Injection",
        description="The software allows user input to be used as the "
                    "expression to eval() or similar language features, "
                    "allowing execution of arbitrary code.",
        severity_hint="critical",
        category="injection",
    ),
    "CWE-77": CWEInfo(
        cwe_id="CWE-77",
        name="Command Injection",
        description="The software constructs all or part of a command using "
                    "externally-influenced input but does not neutralize or "
                    "incorrectly neutralizes special elements.",
        severity_hint="critical",
        category="injection",
    ),
    "CWE-96": CWEInfo(
        cwe_id="CWE-96",
        name="OS Command Injection - Generic",
        description="The software constructs all or part of an OS command "
                    "in an OS command shell using externally-influenced input.",
        severity_hint="critical",
        category="injection",
    ),
    "CWE-90": CWEInfo(
        cwe_id="CWE-90",
        name="LDAP Injection",
        description="The software constructs all or part of an LDAP query "
                    "using externally-influenced input.",
        severity_hint="high",
        category="injection",
    ),
    "CWE-643": CWEInfo(
        cwe_id="CWE-643",
        name="XPath Injection",
        description="The software uses externally-influenced input to construct "
                    "an XPath query used to retrieve data from an XML database.",
        severity_hint="high",
        category="injection",
    ),

    "CWE-798": CWEInfo(
        cwe_id="CWE-798",
        name="Use of Hard-coded Credentials",
        description="The software contains hard-coded credentials, such as "
                    "a password or cryptographic key, which it uses for its "
                    "own inbound authentication, outbound communication, or "
                    "encryption of internal data.",
        severity_hint="critical",
        category="authentication",
    ),
    "CWE-259": CWEInfo(
        cwe_id="CWE-259",
        name="Use of Hard-coded Password",
        description="The software contains a hard-coded password, which it "
                    "uses for its own inbound authentication or for outbound "
                    "communication.",
        severity_hint="critical",
        category="authentication",
    ),
    "CWE-321": CWEInfo(
        cwe_id="CWE-321",
        name="Use of Hard-coded Cryptographic Key",
        description="The software contains a hard-coded cryptographic key "
                    "used for encryption or decryption.",
        severity_hint="critical",
        category="cryptography",
    ),
    "CWE-327": CWEInfo(
        cwe_id="CWE-327",
        name="Use of Broken or Risky Cryptographic Algorithm",
        description="The software uses a broken or risky cryptographic "
                    "algorithm or protocol.",
        severity_hint="high",
        category="cryptography",
    ),
    "CWE-328": CWEInfo(
        cwe_id="CWE-328",
        name="Reversible One-Way Hash",
        description="The software uses a hashing algorithm that is not "
                    "cryptographically strong or uses a reversible hash.",
        severity_hint="high",
        category="cryptography",
    ),
    "CWE-330": CWEInfo(
        cwe_id="CWE-330",
        name="Use of Insufficiently Random Values",
        description="The software uses insufficiently random numbers or "
                    "values in a security context.",
        severity_hint="medium",
        category="cryptography",
    ),
    "CWE-347": CWEInfo(
        cwe_id="CWE-347",
        name="Improper Verification of Cryptographic Signature",
        description="The software does not verify, or incorrectly verifies, "
                    "the cryptographic signature for data.",
        severity_hint="high",
        category="cryptography",
    ),
    "CWE-522": CWEInfo(
        cwe_id="CWE-522",
        name="Insufficiently Protected Credentials",
        description="The software transmits or stores credentials in a way "
                    "that is not sufficiently protected.",
        severity_hint="high",
        category="authentication",
    ),
    "CWE-200": CWEInfo(
        cwe_id="CWE-200",
        name="Exposure of Sensitive Information",
        description="The software exposes sensitive information to an actor "
                    "that is not explicitly authorized to have access.",
        severity_hint="medium",
        category="information-disclosure",
    ),
    "CWE-201": CWEInfo(
        cwe_id="CWE-201",
        name="Insertion of Sensitive Information Into Sent Data",
        description="The software transmits sensitive or security-critical "
                    "data in cleartext in a communication channel.",
        severity_hint="medium",
        category="information-disclosure",
    ),
    "CWE-312": CWEInfo(
        cwe_id="CWE-312",
        name="Cleartext Storage of Sensitive Information",
        description="The software stores sensitive information in cleartext "
                    "in a persistent storage location.",
        severity_hint="medium",
        category="information-disclosure",
    ),
    "CWE-319": CWEInfo(
        cwe_id="CWE-319",
        name="Cleartext Transmission of Sensitive Information",
        description="The software transmits sensitive or security-critical "
                    "data in cleartext in a communication channel.",
        severity_hint="medium",
        category="information-disclosure",
    ),

    "CWE-502": CWEInfo(
        cwe_id="CWE-502",
        name="Deserialization of Untrusted Data",
        description="The application deserializes untrusted data without "
                    "sufficiently verifying that the resulting data will be valid.",
        severity_hint="critical",
        category="deserialization",
    ),
    "CWE-611": CWEInfo(
        cwe_id="CWE-611",
        name="Improper Restriction of XML External Entity Reference",
        description="The software processes an XML document that can contain "
                    "XML entities with URIs that resolve to documents outside "
                    "the intended sphere of control.",
        severity_hint="high",
        category="xml",
    ),

    "CWE-22": CWEInfo(
        cwe_id="CWE-22",
        name="Path Traversal",
        description="The software uses external input to construct a pathname "
                    "that is intended to identify a file or directory beneath "
                    "a restricted parent directory.",
        severity_hint="high",
        category="path-traversal",
    ),
    "CWE-73": CWEInfo(
        cwe_id="CWE-73",
        name="External Control of File Name or Path",
        description="The software allows user input to control or influence "
                    "paths or file names used in filesystem operations.",
        severity_hint="high",
        category="path-traversal",
    ),
    "CWE-434": CWEInfo(
        cwe_id="CWE-434",
        name="Unrestricted Upload of File with Dangerous Type",
        description="The software allows the attacker to upload or transfer "
                    "files of dangerous types that can be automatically processed "
                    "within the product's environment.",
        severity_hint="high",
        category="file-handling",
    ),

    "CWE-16": CWEInfo(
        cwe_id="CWE-16",
        name="Configuration",
        description="The software has a configuration setting that is not "
                    "properly secured or is set to an insecure default value.",
        severity_hint="medium",
        category="configuration",
    ),
    "CWE-215": CWEInfo(
        cwe_id="CWE-215",
        name="Insertion of Sensitive Information Into Debugging Code",
        description="The application inserts sensitive information into "
                    "debugging code or debug messages.",
        severity_hint="low",
        category="information-disclosure",
    ),
    "CWE-284": CWEInfo(
        cwe_id="CWE-284",
        name="Improper Access Control",
        description="The software does not restrict or incorrectly restricts "
                    "access to a resource from an unauthorized actor.",
        severity_hint="high",
        category="access-control",
    ),
    "CWE-285": CWEInfo(
        cwe_id="CWE-285",
        name="Improper Authorization",
        description="The software does not perform or incorrectly performs "
                    "an authorization check when an actor attempts to access "
                    "a resource or perform an action.",
        severity_hint="high",
        category="access-control",
    ),
    "CWE-862": CWEInfo(
        cwe_id="CWE-862",
        name="Missing Authorization",
        description="The software does not perform an authorization check "
                    "when an actor attempts to access a resource or perform "
                    "an action.",
        severity_hint="high",
        category="access-control",
    ),
    "CWE-863": CWEInfo(
        cwe_id="CWE-863",
        name="Incorrect Authorization",
        description="The software performs an authorization check, but the "
                    "check is incorrect.",
        severity_hint="high",
        category="access-control",
    ),

    "CWE-326": CWEInfo(
        cwe_id="CWE-326",
        name="Inadequate Encryption Strength",
        description="The software stores or transmits sensitive data using "
                    "an encryption scheme that is theoretically sound, but "
                    "is not strong enough for the level of protection required.",
        severity_hint="medium",
        category="cryptography",
    ),
    "CWE-329": CWEInfo(
        cwe_id="CWE-329",
        name="Not Using an Unpredictable IV with CBC Mode",
        description="The software uses a cryptographic algorithm in CBC "
                    "mode with a non-random or predictable IV.",
        severity_hint="medium",
        category="cryptography",
    ),
    "CWE-338": CWEInfo(
        cwe_id="CWE-338",
        name="Use of Cryptographically Weak PRNG",
        description="The software uses a Pseudo-Random Number Generator "
                    "(PRNG) in a security context, but the PRNG's algorithm "
                    "is not cryptographically strong.",
        severity_hint="medium",
        category="cryptography",
    ),

    "CWE-20": CWEInfo(
        cwe_id="CWE-20",
        name="Improper Input Validation",
        description="The software receives input or data, but it does not "
                    "validate or incorrectly validates that the input has "
                    "the properties that are required to process the data "
                    "safely and correctly.",
        severity_hint="medium",
        category="input-validation",
    ),
    "CWE-787": CWEInfo(
        cwe_id="CWE-787",
        name="Out-of-bounds Write",
        description="The software writes data past the end, or before the "
                    "beginning, of the intended buffer.",
        severity_hint="critical",
        category="memory-safety",
    ),
    "CWE-125": CWEInfo(
        cwe_id="CWE-125",
        name="Out-of-bounds Read",
        description="The software reads data past the end, or before the "
                    "beginning, of the intended buffer.",
        severity_hint="medium",
        category="memory-safety",
    ),

    "CWE-362": CWEInfo(
        cwe_id="CWE-362",
        name="Race Condition",
        description="The software contains a code path that may lead to a "
                    "race condition in concurrent execution scenarios.",
        severity_hint="medium",
        category="concurrency",
    ),
    "CWE-367": CWEInfo(
        cwe_id="CWE-367",
        name="Time-of-check Time-of-use (TOCTOU) Race Condition",
        description="The software checks the state of a resource before "
                    "using that resource, but the resource's state can change "
                    "between the check and the use.",
        severity_hint="medium",
        category="concurrency",
    ),

    "CWE-613": CWEInfo(
        cwe_id="CWE-613",
        name="Session Expiration Not Implemented",
        description="The application does not invalidate session identifiers "
                    "on logout or other explicit session termination events.",
        severity_hint="medium",
        category="session",
    ),
    "CWE-384": CWEInfo(
        cwe_id="CWE-384",
        name="Session Fixation",
        description="The application does not generate a new session ID "
                    "after successful authentication.",
        severity_hint="high",
        category="session",
    ),

    "CWE-918": CWEInfo(
        cwe_id="CWE-918",
        name="Server-Side Request Forgery (SSRF)",
        description="The software receives input from an upstream component "
                    "and uses that input to construct a server-side request.",
        severity_hint="high",
        category="ssrf",
    ),
    "CWE-601": CWEInfo(
        cwe_id="CWE-601",
        name="URL Redirect to Untrusted Site (Open Redirect)",
        description="The application accepts user-controlled input that "
                    "specifies a link to an external site.",
        severity_hint="medium",
        category="redirect",
    ),

    "CWE-778": CWEInfo(
        cwe_id="CWE-778",
        name="Insufficient Logging",
        description="The software does not write sufficient audit information "
                    "to a logging mechanism.",
        severity_hint="low",
        category="logging",
    ),
    "CWE-532": CWEInfo(
        cwe_id="CWE-532",
        name="Insertion of Sensitive Information into Log File",
        description="The software writes sensitive information to a log file.",
        severity_hint="medium",
        category="logging",
    ),

    "CWE-617": CWEInfo(
        cwe_id="CWE-617",
        name="Reachable Assertion",
        description="The software contains an assert() or similar statement "
                    "that can be triggered by an attacker, causing the "
                    "application to crash or exit.",
        severity_hint="medium",
        category="logic",
    ),
    "CWE-697": CWEInfo(
        cwe_id="CWE-697",
        name="Incorrect Comparison",
        description="The software compares values incorrectly, leading to "
                    "incorrect logic or control flow.",
        severity_hint="low",
        category="logic",
    ),
    "CWE-400": CWEInfo(
        cwe_id="CWE-400",
        name="Uncontrolled Resource Consumption",
        description="The software does not properly control the allocation "
                    "and maintenance of a limited resource.",
        severity_hint="medium",
        category="resource",
    ),
    "CWE-733": CWEInfo(
        cwe_id="CWE-733",
        name="Compiler Optimization Removal or Modification of Security-critical Code",
        description="The developer uses a compiler optimization that removes "
                    "security-critical code, such as assertions.",
        severity_hint="medium",
        category="configuration",
    ),
    "CWE-295": CWEInfo(
        cwe_id="CWE-295",
        name="Improper Certificate Validation",
        description="The software does not validate, or incorrectly validates, "
                    "a certificate.",
        severity_hint="high",
        category="cryptography",
    ),
    "CWE-297": CWEInfo(
        cwe_id="CWE-297",
        name="Improper Validation of Certificate with Host Mismatch",
        description="The software communicates with a host, but it does not "
                    "properly verify that the host's certificate is valid for "
                    "the intended host.",
        severity_hint="medium",
        category="cryptography",
    ),
    "CWE-311": CWEInfo(
        cwe_id="CWE-311",
        name="Missing Authentication for Critical Function",
        description="The software does not require authentication for "
                    "critical functionality.",
        severity_hint="high",
        category="authentication",
    ),
    "CWE-306": CWEInfo(
        cwe_id="CWE-306",
        name="Missing Authentication for Critical Function",
        description="The software does not perform any authentication for "
                    "functionality that requires a provable user identity.",
        severity_hint="high",
        category="authentication",
    ),
    "CWE-250": CWEInfo(
        cwe_id="CWE-250",
        name="Execution with Unnecessary Privileges",
        description="The software performs an operation at a privilege level "
                    "that is above the minimum level required.",
        severity_hint="medium",
        category="access-control",
    ),
    "CWE-668": CWEInfo(
        cwe_id="CWE-668",
        name="Exposure of Resource to Wrong Sphere",
        description="The software exposes a resource to the wrong sphere.",
        severity_hint="medium",
        category="access-control",
    ),
    "CWE-918": CWEInfo(
        cwe_id="CWE-918",
        name="Server-Side Request Forgery",
        description="The web server receives a URL from a user and retrieves "
                    "the contents of that URL, but does not sufficiently "
                    "restrict the target URL.",
        severity_hint="high",
        category="ssrf",
    ),
    "CWE-1037": CWEInfo(
        cwe_id="CWE-1037",
        name="Processor Optimization Removal or Modification of Security-critical Code",
        description="The software uses security-critical code that can be "
                    "optimized or removed by a processor.",
        severity_hint="medium",
        category="configuration",
    ),
    "CWE-1321": CWEInfo(
        cwe_id="CWE-1321",
        name="Improperly Controlled Modification of Object Prototype Attributes",
        description="The software is susceptible to prototype pollution, "
                    "allowing an attacker to modify prototype attributes.",
        severity_hint="high",
        category="injection",
    ),
}


# Maps Bandit rule IDs (e.g., "B608") to CWE identifiers.

BANDIT_TO_CWE: Dict[str, str] = {
    # SQL injection
    "B608": "CWE-89",
    "B609": "CWE-89",
    # eval/exec usage
    "B307": "CWE-95",
    "B102": "CWE-95",
    # Shell injection
    "B602": "CWE-78",
    "B603": "CWE-78",
    "B604": "CWE-78",
    "B605": "CWE-78",
    "B606": "CWE-78",
    # Subprocess with shell=True
    "B602": "CWE-78",
    # Pickle deserialization
    "B301": "CWE-502",
    "B304": "CWE-502",
    # XML processing
    "B506": "CWE-611",
    "B405": "CWE-611",
    # Hardcoded credentials
    "B105": "CWE-259",
    "B106": "CWE-259",
    "B107": "CWE-259",
    # Insecure hashing
    "B303": "CWE-327",
    "B324": "CWE-328",
    # Insecure SSL/TLS
    "B501": "CWE-295",
    "B502": "CWE-295",
    # Insecure random
    "B311": "CWE-330",
    # Assert statements
    "B101": "CWE-617",
    # Flask / Jinja2 autoescape
    "B701": "CWE-79",
    "B702": "CWE-79",
    # Tarfile extraction
    "B202": "CWE-22",
    "B201": "CWE-22",
    # Try/except pass
    "B110": "CWE-390",
    "B112": "CWE-390",
    # Hardcoded temp directories
    "B108": "CWE-22",
    # Insecure FTP
    "B401": "CWE-319",
    # Input validation
    "B503": "CWE-20",
    "B504": "CWE-20",
    # YAML loading
    "B506": "CWE-502",
}


# Maps common Semgrep rule IDs to CWE identifiers.

SEMGREP_TO_CWE: Dict[str, str] = {
    "python.lang.security.audit.dangerous-system-call": "CWE-78",
    "python.lang.security.audit.dangerous-exec": "CWE-95",
    "python.lang.security.audit.dangerous-eval": "CWE-95",
    "python.lang.security.audit.subprocess-shell-true": "CWE-78",
    "python.lang.security.audit.sql-injection": "CWE-89",
    "python.lang.security.audit.pickle-load": "CWE-502",
    "python.lang.security.audit.yaml-load": "CWE-502",
    "python.lang.security.audit.hardcoded-password": "CWE-259",
    "python.lang.security.audit.insecure-hash": "CWE-327",
    "python.lang.security.audit.assert-used": "CWE-617",
    "python.lang.security.audit.md5-used": "CWE-327",
    "python.lang.security.audit.sha1-used": "CWE-327",
    "python.lang.security.audit.ssl-no-verify": "CWE-295",
    "python.lang.security.injection.sqlalchemy": "CWE-89",
    "python.lang.security.injection.raw-sql": "CWE-89",
    "python.flask.security.audit.xss-response": "CWE-79",
    "python.django.security.audit.xss-response": "CWE-79",
    "javascript.lang.security.audit.dangerous-eval": "CWE-95",
    "javascript.lang.security.audit.prototype-pollution": "CWE-1321",
    "javascript.lang.security.audit.regex-dos": "CWE-400",
}


# Maps SecureBuild internal rule IDs to CWE identifiers.

INTERNAL_RULE_TO_CWE: Dict[str, str] = {
    # SAST internal rules
    "sast-sql-injection": "CWE-89",
    "sast-eval-usage": "CWE-95",
    "sast-exec-usage": "CWE-95",
    "sast-shell-true": "CWE-78",
    "sast-pickle-load": "CWE-502",
    "sast-yaml-load": "CWE-502",
    "sast-insecure-hash": "CWE-327",
    "sast-http-url": "CWE-319",
    "sast-assert-statement": "CWE-617",
    "sast-input-validation": "CWE-20",
    # Secrets internal rules
    "secrets-aws-access-key": "CWE-798",
    "secrets-aws-secret-key": "CWE-798",
    "secrets-github-pat": "CWE-798",
    "secrets-stripe-key": "CWE-798",
    "secrets-jwt-token": "CWE-321",
    "secrets-private-key": "CWE-321",
    "secrets-password": "CWE-259",
    "secrets-api-key": "CWE-798",
    "secrets-generic-secret": "CWE-798",
    "secrets-high-entropy": "CWE-200",
    "secrets-env-credential": "CWE-798",
    # CVE / dependency rules
    "cve-known-vulnerability": "CWE-918",
    "cve-stale-dependency": "CWE-1104",
    "cve-license-compliance": "CWE-668",
}


def get_cwe_info(cwe_id: str) -> Optional[CWEInfo]:
    return CWE_DATABASE.get(cwe_id)


def bandit_to_cwe(bandit_id: str) -> str:
    return BANDIT_TO_CWE.get(bandit_id, "CWE-20")


def semgrep_to_cwe(semgrep_id: str) -> str:
    return SEMGREP_TO_CWE.get(semgrep_id, "CWE-20")


def rule_to_cwe(rule_id: str) -> str:
    # Try Bandit mapping
    if rule_id.startswith("B"):
        cwe = BANDIT_TO_CWE.get(rule_id)
        if cwe:
            return cwe

    # Try internal mapping
    cwe = INTERNAL_RULE_TO_CWE.get(rule_id)
    if cwe:
        return cwe

    # Try Semgrep mapping
    cwe = SEMGREP_TO_CWE.get(rule_id)
    if cwe:
        return cwe

    return "CWE-20"
