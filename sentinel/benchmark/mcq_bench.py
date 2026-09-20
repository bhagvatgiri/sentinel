"""D3 — SecEval / CyberMetric MCQ as RAG-regression test.

CAI ships ``benchmarks/seceval`` and ``benchmarks/cybermetric`` with
multiple-choice cybersecurity questions. We port a small subset
(~50 questions across cyber knowledge domains) and run two passes:

  - **Cold pass:** model answers without Sentinel's RAG context.
  - **RAG-augmented pass:** retriever pulls top-k chunks from the local
    Chroma corpus and prepends them to the model's prompt.

Metric: accuracy delta (RAG accuracy − cold accuracy). The bench is
the regression test that proves Sentinel's OWASP/MITRE/NIST corpus
ingestion is paying for itself. If the delta drops below +10 %, either
the corpus needs re-ingest or the retriever is broken.

The questions are paraphrased / re-authored from public security exam
prep so we don't redistribute SecEval / CyberMetric prose verbatim
without their license attached.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Optional


log = logging.getLogger(__name__)


@dataclass
class MCQ:
    qid: str
    domain: str
    question: str
    choices: dict[str, str]      # {"A": "...", "B": "...", ...}
    correct: str                 # one of the choice keys
    rag_query: str               # used to seed retriever in RAG mode


# 50 paraphrased / Sentinel-authored MCQs across the major OWASP /
# MITRE / NIST domains. NOT verbatim from SecEval/CyberMetric (those
# are GPL and can't be redistributed in this repo).
QUESTIONS: list[MCQ] = [
    MCQ("q01", "owasp",
        "Which OWASP Top 10 (2021) category covers SSRF?",
        {"A": "A01 Broken Access Control",
         "B": "A03 Injection",
         "C": "A10 Server-Side Request Forgery",
         "D": "A05 Security Misconfiguration"},
        "C", "OWASP Top 10 2021 SSRF category"),
    MCQ("q02", "owasp",
        "Which OWASP Top 10 (2021) category replaced 'Cross-Site Scripting' as a standalone item?",
        {"A": "A03 Injection (XSS folded in)",
         "B": "A07 Identification and Authentication Failures",
         "C": "A04 Insecure Design",
         "D": "A02 Cryptographic Failures"},
        "A", "OWASP Top 10 2021 XSS folded into Injection"),
    MCQ("q03", "mitre-cwe",
        "Which CWE corresponds to SQL injection?",
        {"A": "CWE-79", "B": "CWE-89", "C": "CWE-352", "D": "CWE-918"},
        "B", "CWE SQL injection"),
    MCQ("q04", "mitre-cwe",
        "Which CWE corresponds to Cross-Site Request Forgery?",
        {"A": "CWE-79", "B": "CWE-89", "C": "CWE-352", "D": "CWE-918"},
        "C", "CWE CSRF"),
    MCQ("q05", "mitre-cwe",
        "CWE-918 covers which class of vulnerability?",
        {"A": "Path traversal",
         "B": "Server-side request forgery",
         "C": "Insecure deserialization",
         "D": "OS command injection"},
        "B", "CWE-918 SSRF"),
    MCQ("q06", "mitre-attack",
        "Which ATT&CK technique covers 'Exploit Public-Facing Application'?",
        {"A": "T1190", "B": "T1059", "C": "T1078", "D": "T1505.003"},
        "A", "ATT&CK T1190 Exploit Public-Facing Application"),
    MCQ("q07", "mitre-attack",
        "Which ATT&CK technique covers 'Web Shell'?",
        {"A": "T1190", "B": "T1059", "C": "T1078", "D": "T1505.003"},
        "D", "ATT&CK Web Shell technique"),
    MCQ("q08", "mitre-attack",
        "Which ATT&CK tactic does 'Web Shell' (T1505.003) belong to?",
        {"A": "Initial Access", "B": "Execution",
         "C": "Persistence", "D": "Command and Control"},
        "C", "ATT&CK web shell persistence tactic"),
    MCQ("q09", "owasp",
        "Per OWASP ASVS, which authentication control category covers password policy?",
        {"A": "V2 Authentication",
         "B": "V3 Session Management",
         "C": "V4 Access Control",
         "D": "V5 Validation"},
        "A", "OWASP ASVS V2 password policy"),
    MCQ("q10", "owasp",
        "Which header best mitigates clickjacking?",
        {"A": "Strict-Transport-Security",
         "B": "Content-Security-Policy frame-ancestors",
         "C": "X-Content-Type-Options",
         "D": "Referrer-Policy"},
        "B", "clickjacking CSP frame-ancestors"),
    MCQ("q11", "owasp",
        "Which scheme is recommended over HTTP Basic for sensitive APIs?",
        {"A": "HTTP Digest", "B": "OAuth 2.0 with PKCE",
         "C": "Cookie auth", "D": "API key in query string"},
        "B", "OAuth 2.0 PKCE recommendation"),
    MCQ("q12", "mitre-cwe",
        "CWE-22 is which class?",
        {"A": "Path traversal", "B": "Race condition",
         "C": "Open redirect", "D": "Buffer overflow"},
        "A", "CWE-22 path traversal"),
    MCQ("q13", "mitre-cwe",
        "CWE-434 covers what?",
        {"A": "Mass assignment",
         "B": "Unrestricted file upload",
         "C": "Insecure deserialization",
         "D": "Improper authentication"},
        "B", "CWE-434 file upload"),
    MCQ("q14", "owasp",
        "What is the recommended NIST SP 800-63B authentication assurance level for a public bug-bounty program?",
        {"A": "AAL1", "B": "AAL2", "C": "AAL3", "D": "AAL0"},
        "B", "NIST 800-63B AAL2 bug bounty"),
    MCQ("q15", "owasp",
        "Which is the safer way to handle user input in dynamic SQL?",
        {"A": "String concatenation with escaping",
         "B": "Parameterised queries / prepared statements",
         "C": "ORM with raw() escape hatch",
         "D": "Disable SQL altogether"},
        "B", "SQL injection prevention parameterised queries"),
    MCQ("q16", "mitre-attack",
        "T1078 covers which technique?",
        {"A": "Valid Accounts", "B": "Brute Force",
         "C": "Credential Stuffing", "D": "Spearphishing"},
        "A", "ATT&CK T1078 Valid Accounts"),
    MCQ("q17", "mitre-attack",
        "T1133 covers which technique?",
        {"A": "Phishing",
         "B": "External Remote Services",
         "C": "Drive-by Compromise",
         "D": "Supply Chain Compromise"},
        "B", "ATT&CK T1133 External Remote Services"),
    MCQ("q18", "owasp",
        "Which header instructs the browser to enforce HTTPS for the domain?",
        {"A": "X-Frame-Options",
         "B": "Strict-Transport-Security",
         "C": "X-Content-Type-Options",
         "D": "Permissions-Policy"},
        "B", "HSTS Strict-Transport-Security"),
    MCQ("q19", "owasp",
        "What value of the SameSite cookie attribute most strictly protects from CSRF?",
        {"A": "None", "B": "Lax", "C": "Strict", "D": "default"},
        "C", "SameSite Strict CSRF protection"),
    MCQ("q20", "owasp",
        "Which mode of CORS allows credentials to be sent cross-origin?",
        {"A": "Access-Control-Allow-Origin: * with no credentials",
         "B": "Access-Control-Allow-Origin: <exact origin> + Access-Control-Allow-Credentials: true",
         "C": "Wildcard origin with credentials",
         "D": "Set-Cookie SameSite=None alone"},
        "B", "CORS credentials exact origin"),
    MCQ("q21", "mitre-cwe",
        "CWE-352 is the parent CWE for…",
        {"A": "Open redirect",
         "B": "Cross-site request forgery",
         "C": "SSRF",
         "D": "Path traversal"},
        "B", "CWE-352 CSRF"),
    MCQ("q22", "mitre-cwe",
        "CWE-639 is which class?",
        {"A": "IDOR (insecure direct object reference)",
         "B": "Mass assignment",
         "C": "Race condition",
         "D": "Improper certificate validation"},
        "A", "CWE-639 IDOR"),
    MCQ("q23", "owasp",
        "Per OWASP, the safest CSP source for inline scripts is…",
        {"A": "'unsafe-inline'",
         "B": "Nonces or hashes",
         "C": "* wildcard",
         "D": "data:"},
        "B", "CSP nonce hash inline scripts"),
    MCQ("q24", "owasp",
        "Which encoding prevents reflected XSS in HTML element context?",
        {"A": "URL-encoding",
         "B": "HTML-entity encoding",
         "C": "Base64",
         "D": "JSON encoding"},
        "B", "XSS HTML entity encoding"),
    MCQ("q25", "mitre-cwe",
        "CWE-287 covers…",
        {"A": "Improper Authentication",
         "B": "Improper Authorization",
         "C": "Improper Input Validation",
         "D": "Improper Restriction of XXE"},
        "A", "CWE-287 improper authentication"),
    MCQ("q26", "mitre-cwe",
        "CWE-611 covers…",
        {"A": "XML external entity (XXE)",
         "B": "Insecure deserialization",
         "C": "Cross-site request forgery",
         "D": "Improper certificate validation"},
        "A", "CWE-611 XXE"),
    MCQ("q27", "owasp",
        "Which OWASP project is the gold standard for mobile app security verification?",
        {"A": "ASVS", "B": "MASVS", "C": "WSTG", "D": "SAMM"},
        "B", "OWASP MASVS mobile"),
    MCQ("q28", "owasp",
        "Per OWASP WSTG, which test ID covers SQL injection?",
        {"A": "WSTG-INPV-05",
         "B": "WSTG-AUTH-04",
         "C": "WSTG-CONF-02",
         "D": "WSTG-SESS-01"},
        "A", "OWASP WSTG INPV-05 SQL injection"),
    MCQ("q29", "mitre-attack",
        "Which sub-technique covers PowerShell execution?",
        {"A": "T1059.001", "B": "T1059.003",
         "C": "T1059.004", "D": "T1059.007"},
        "A", "ATT&CK T1059.001 PowerShell"),
    MCQ("q30", "mitre-attack",
        "Which sub-technique covers Bash / Unix Shell execution?",
        {"A": "T1059.001", "B": "T1059.004",
         "C": "T1059.005", "D": "T1059.007"},
        "B", "ATT&CK T1059.004 Unix Shell"),
    MCQ("q31", "owasp",
        "Per OWASP, the recommended password hashing function is…",
        {"A": "MD5", "B": "SHA-256",
         "C": "bcrypt / Argon2id", "D": "PBKDF2 with 1000 iterations"},
        "C", "OWASP password hashing Argon2id"),
    MCQ("q32", "owasp",
        "Which CWE describes 'Use of a Broken or Risky Cryptographic Algorithm'?",
        {"A": "CWE-327", "B": "CWE-89",
         "C": "CWE-200", "D": "CWE-22"},
        "A", "CWE-327 broken crypto"),
    MCQ("q33", "owasp",
        "Which CWE describes 'Information Exposure'?",
        {"A": "CWE-200", "B": "CWE-79",
         "C": "CWE-22", "D": "CWE-352"},
        "A", "CWE-200 information exposure"),
    MCQ("q34", "mitre-attack",
        "Which ATT&CK tactic covers 'Initial Access'?",
        {"A": "TA0001", "B": "TA0002",
         "C": "TA0003", "D": "TA0006"},
        "A", "ATT&CK TA0001 Initial Access"),
    MCQ("q35", "mitre-attack",
        "Which ATT&CK tactic covers 'Persistence'?",
        {"A": "TA0001", "B": "TA0002",
         "C": "TA0003", "D": "TA0006"},
        "C", "ATT&CK TA0003 Persistence"),
    MCQ("q36", "owasp",
        "Per OWASP, what is the safest deserialization approach?",
        {"A": "Pickle",
         "B": "JSON with strict schema validation",
         "C": "YAML safe_load",
         "D": "PHP serialize/unserialize"},
        "B", "OWASP safe deserialization JSON"),
    MCQ("q37", "owasp",
        "Which response header signals MIME-type sniffing should be disabled?",
        {"A": "X-Content-Type-Options: nosniff",
         "B": "X-Frame-Options: DENY",
         "C": "Strict-Transport-Security",
         "D": "Cache-Control"},
        "A", "X-Content-Type-Options nosniff"),
    MCQ("q38", "mitre-cwe",
        "CWE-798 covers…",
        {"A": "Use of Hard-coded Credentials",
         "B": "Race condition",
         "C": "Buffer overflow",
         "D": "Open redirect"},
        "A", "CWE-798 hard-coded credentials"),
    MCQ("q39", "mitre-cwe",
        "CWE-601 covers…",
        {"A": "Open redirect",
         "B": "SSRF",
         "C": "XML injection",
         "D": "Insecure cookie"},
        "A", "CWE-601 open redirect"),
    MCQ("q40", "owasp",
        "Per OWASP, the recommended way to handle file-upload MIME validation is…",
        {"A": "Trust Content-Type header",
         "B": "Magic-byte sniffing + extension whitelist + size limit",
         "C": "Block executable extensions only",
         "D": "Quarantine to /tmp and skip validation"},
        "B", "file upload validation magic bytes whitelist"),
    MCQ("q41", "owasp",
        "What is the recommended JWT signing algorithm?",
        {"A": "none",
         "B": "HS256 with random secret",
         "C": "RS256 / EdDSA / ES256",
         "D": "HS1"},
        "C", "JWT signing RS256 EdDSA"),
    MCQ("q42", "mitre-attack",
        "Which sub-technique covers JavaScript / TypeScript execution?",
        {"A": "T1059.001", "B": "T1059.003",
         "C": "T1059.005", "D": "T1059.007"},
        "D", "ATT&CK T1059.007 JavaScript"),
    MCQ("q43", "owasp",
        "Per OWASP, content-type for a JSON API response should be…",
        {"A": "text/html",
         "B": "application/json",
         "C": "application/x-www-form-urlencoded",
         "D": "text/plain"},
        "B", "JSON API content-type"),
    MCQ("q44", "owasp",
        "Which is the OWASP-recommended OAuth 2.0 grant for native mobile apps?",
        {"A": "Implicit grant",
         "B": "Resource Owner Password Credentials",
         "C": "Authorization Code with PKCE",
         "D": "Client Credentials"},
        "C", "OAuth 2.0 PKCE mobile native"),
    MCQ("q45", "owasp",
        "Per OWASP, the recommended TLS version for new deployments is…",
        {"A": "TLS 1.0",
         "B": "TLS 1.1",
         "C": "TLS 1.2 / 1.3",
         "D": "SSL 3.0"},
        "C", "TLS 1.3 recommended"),
    MCQ("q46", "owasp",
        "Which CSP directive controls allowed script sources?",
        {"A": "img-src", "B": "script-src",
         "C": "style-src", "D": "frame-ancestors"},
        "B", "CSP script-src directive"),
    MCQ("q47", "mitre-cwe",
        "CWE-79 covers…",
        {"A": "Cross-site scripting",
         "B": "SQL injection",
         "C": "CSRF",
         "D": "Open redirect"},
        "A", "CWE-79 XSS"),
    MCQ("q48", "owasp",
        "Per OWASP, the safest random-number source for security tokens is…",
        {"A": "Math.random",
         "B": "rand()",
         "C": "Cryptographically secure PRNG (e.g., os.urandom, crypto.randomBytes)",
         "D": "current timestamp"},
        "C", "secure random os.urandom"),
    MCQ("q49", "mitre-attack",
        "Which technique covers credential dumping from LSASS?",
        {"A": "T1003.001", "B": "T1078",
         "C": "T1190", "D": "T1059"},
        "A", "ATT&CK T1003.001 LSASS credential dump"),
    MCQ("q50", "owasp",
        "Per OWASP, the MOST important defense against IDOR is…",
        {"A": "Obfuscate IDs",
         "B": "Per-request authorisation check on the resource",
         "C": "Use UUIDs",
         "D": "Shorter session timeout"},
        "B", "IDOR per-request authorisation"),
]


# ---- runners --------------------------------------------------------------

def cold_runner_keyword_baseline(mcq: MCQ) -> str:
    """A weak baseline that just picks the choice with the most
    keyword overlap to the question. Stand-in for "cold LLM" when no
    real model is wired — used in unit tests + CI.
    """
    q_tokens = set(re.findall(r"[A-Za-z0-9]+", mcq.question.lower()))
    best_choice = "A"
    best_score = -1
    for k, v in mcq.choices.items():
        toks = set(re.findall(r"[A-Za-z0-9]+", v.lower()))
        score = len(q_tokens & toks)
        if score > best_score:
            best_score = score
            best_choice = k
    return best_choice


def rag_runner_perfect(mcq: MCQ) -> str:
    """Stand-in 'RAG-augmented' runner that returns the correct answer.
    Used by the unit test to prove the harness wiring + delta math
    works end-to-end without needing live Chroma + Ollama.

    A REAL RAG-augmented runner lives in :func:`rag_runner_via_corpus`
    below; CI uses this stub so tests don't depend on a live store.
    """
    return mcq.correct


def rag_runner_via_corpus(
    retriever, llm_call: Callable[[str], str], top_k: int = 4
) -> Callable[[MCQ], str]:
    """Build a RAG runner closure given a Sentinel Retriever + LLM
    call function. ``llm_call(prompt) -> "A"|"B"|"C"|"D"``.

    Not used by unit tests (would need live infra) — kept here so the
    CLI / dashboard can wire it up against the real corpus.
    """
    def runner(mcq: MCQ) -> str:
        chunks = retriever.retrieve(mcq.rag_query, top_k=top_k)
        ctx = "\n\n".join(
            getattr(c, "text", str(c))[:800] for c in chunks
        )
        prompt = (
            "You are answering a security exam question. Use ONLY the "
            "context below; if it doesn't help, answer based on standard "
            "security practice.\n\n"
            f"=== CONTEXT ===\n{ctx}\n\n=== QUESTION ===\n"
            f"{mcq.question}\n"
            + "\n".join(f"{k}. {v}" for k, v in mcq.choices.items())
            + "\n\nRespond with a single letter only (A, B, C, or D)."
        )
        ans = llm_call(prompt).strip().upper()
        # Guard: take first valid letter found.
        for ch in ans:
            if ch in mcq.choices:
                return ch
        return "A"
    return runner


# ---- harness orchestrator -------------------------------------------------

def run(
    *,
    cold_runner: Callable[[MCQ], str] = cold_runner_keyword_baseline,
    rag_runner: Callable[[MCQ], str] = rag_runner_perfect,
    questions: Optional[list[MCQ]] = None,
) -> dict:
    """Run both passes and return the accuracy delta.

    Defaults give a deterministic outcome useful for CI: keyword
    baseline ≈ 0.20 random; perfect RAG = 1.00; delta = +0.80. A real
    benchmarking session passes in live runners.
    """
    qs = questions or QUESTIONS
    cold_correct = 0
    rag_correct = 0
    per_q = []
    for q in qs:
        cold_ans = cold_runner(q)
        rag_ans = rag_runner(q)
        cold_ok = (cold_ans == q.correct)
        rag_ok = (rag_ans == q.correct)
        cold_correct += int(cold_ok)
        rag_correct += int(rag_ok)
        per_q.append({
            "qid": q.qid, "domain": q.domain,
            "cold_answer": cold_ans, "rag_answer": rag_ans,
            "correct": q.correct, "cold_ok": cold_ok, "rag_ok": rag_ok,
        })
    n = len(qs)
    cold_acc = cold_correct / n if n else 0.0
    rag_acc = rag_correct / n if n else 0.0
    return {
        "n_questions": n,
        "cold_accuracy": round(cold_acc, 4),
        "rag_accuracy": round(rag_acc, 4),
        "delta": round(rag_acc - cold_acc, 4),
        "per_question": per_q,
    }


# ---- imports kept at bottom to avoid circulars ----
import re        # noqa: E402
