# 🌐 CSP Validator

A **client-side, OWASP-aligned Content Security Policy (CSP) validator & hardener**.

This is designed for **security engineers, bug bounty hunters, pentesters, and developers** who want instant CSP analysis **without sending data to any server**.

---

## 🚀 Features:

✅ Paste any CSP header and analyze it instantly.  
✅ Detect **real, exploitable CSP weaknesses only**.  
✅ Preserve user domains while hardening securely.  
✅ OWASP based strict CSP hardening logic.  
✅ Dynamic, accurate suggestions based on **actual changes**.  
✅ Raw payloads displayed safely.  
✅ No backend, no tracking, no network calls.  

---

## 🧠 What This Tool Detects:

| Directive | What is Detected |
|---------|------------------|
| `default-src` | Wildcards (`*`) |
| `script-src` | `unsafe-inline`, wildcards, JSONP-capable domains |
| `style-src` | Inline styles |
| `img-src` | Dangerous `data:` usage |
| `object-src` | Missing or permissive values |
| `frame-ancestors` | Clickjacking risks |
| Missing directives | OWASP-required CSP directives |

Only **real-world exploitable issues** are shown.

---

## 🛡 Hardened CSP Logic:

- Sets `default-src 'none'`
- Enforces **nonce + strict-dynamic**
- Preserves user domains (upgraded to HTTPS)
- Adds missing OWASP-recommended directives
- Enables Trusted Types
- Blocks mixed content
- Prevents clickjacking & plugin abuse

> ⚠️ If risky domains are preserved, the tool clearly flags them.

---

## 🧪 Payload System: (Contribution friendly)

Payloads are mapped **per directive** and stored safely:

```js
const PAYLOADS = {
  "script-src": [
    "&lt;script src=\"https://evil.example/x.js\"&gt;&lt;/script&gt;"
  ],
  "img-src": [
    "&lt;img src=x onerror=alert(1)&gt;"
  ]
};
```

> Can contribute in this format


---

## 🧩 Missing / Optional CSP Directives (Advanced):

The tool can also handle:

- `report-uri` / `report-to`
- `sandbox`
- `plugin-types`
- `frame-src`

---

## 🧑‍💻 Author:

Made with ❤️ by **th3.d1p4k**

---

## ⚠️ Disclaimer

This tool is intended for **security testing and defensive hardening only**.  
Use responsibly and only on systems you own or have permission to test.
