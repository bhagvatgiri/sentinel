"""Browseable payload catalog (Phase 8 library).

Renders the curated `sentinel/agent/pentest/payloads/{auth,injection,xss,ssrf}`
sets so the operator can copy a known-good payload by hand without spinning up
the agent. Per-class index, per-subtype list, search across name + payload +
notes.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from sentinel.agent.pentest import payloads as payload_bank


router = APIRouter()


@router.get("/payloads", name="payloads_index")
def payloads_index(request: Request, q: str = Query("", max_length=200)):
    classes = payload_bank.all_classes()
    rows: list[dict] = []
    for c in classes:
        rows.append({
            "class": c,
            "subtypes": payload_bank.available_subtypes(c),
            "n_subtypes": len(payload_bank.available_subtypes(c)),
        })
    matches: list[dict] = []
    if q:
        ql = q.lower().strip()
        for c in classes:
            for st in payload_bank.available_subtypes(c):
                for p in payload_bank.get_payloads(c, st, limit=50):
                    haystack = f"{p['name']} {p['payload']} {p.get('notes','')}".lower()
                    if ql in haystack:
                        matches.append({
                            "class": c, "subtype": st,
                            "name": p["name"], "payload": p["payload"],
                            "notes": p.get("notes", ""),
                        })
    return request.app.state.templates.TemplateResponse(
        request, "payloads.html",
        {
            "active_nav": "Payloads",
            "rows": rows,
            "selected_class": None,
            "selected_subtype": None,
            "payloads": [],
            "q": q,
            "matches": matches,
        },
    )


@router.get("/payloads/{class_}", name="payloads_class")
def payloads_class(class_: str, request: Request):
    if class_ not in payload_bank.all_classes():
        raise HTTPException(404, f"unknown class {class_!r}")
    return request.app.state.templates.TemplateResponse(
        request, "payloads.html",
        {
            "active_nav": "Payloads",
            "rows": [{
                "class": c,
                "subtypes": payload_bank.available_subtypes(c),
                "n_subtypes": len(payload_bank.available_subtypes(c)),
            } for c in payload_bank.all_classes()],
            "selected_class": class_,
            "selected_subtype": None,
            "subtypes": payload_bank.available_subtypes(class_),
            "payloads": [],
            "q": "",
            "matches": [],
        },
    )


@router.get("/payloads/{class_}/{subtype}", name="payloads_subtype")
def payloads_subtype(class_: str, subtype: str, request: Request):
    if class_ not in payload_bank.all_classes():
        raise HTTPException(404, f"unknown class {class_!r}")
    if subtype not in payload_bank.available_subtypes(class_):
        raise HTTPException(404, f"unknown subtype {subtype!r} for class {class_!r}")
    payloads = payload_bank.get_payloads(class_, subtype, limit=200)
    return request.app.state.templates.TemplateResponse(
        request, "payloads.html",
        {
            "active_nav": "Payloads",
            "rows": [{
                "class": c,
                "subtypes": payload_bank.available_subtypes(c),
                "n_subtypes": len(payload_bank.available_subtypes(c)),
            } for c in payload_bank.all_classes()],
            "selected_class": class_,
            "selected_subtype": subtype,
            "subtypes": payload_bank.available_subtypes(class_),
            "payloads": payloads,
            "q": "",
            "matches": [],
        },
    )
