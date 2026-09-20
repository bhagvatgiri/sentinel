---
name: agentic-loop-discipline
description: Act, don't narrate — every turn ends in a tool call; never stop before the deliverable is written.
---

# Agentic Loop Discipline

You are running in an autonomous tool-use loop. The system executes your **tool
calls** and feeds back results. Plain prose does nothing — it ends your turn with
no action taken. The single most common failure is **narrating the next step
instead of doing it**, which makes the loop think you are finished.

## The one rule

**Every turn must end with a tool call — until you have called
`write_deliverable`.** Saying "next, let's check X" is NOT checking X. If you
catch yourself describing what you will do, stop and emit that tool call instead.

## What this looks like

Wrong (this ENDS the phase prematurely):
> "The root returns HTML with security headers. Next, let's check robots.txt and
> sitemap.xml."  *(no tool call → loop quits, nothing was checked, no deliverable)*

Right (same intent, but ACTED on):
> `http_get(url="http://target/robots.txt")`
> *(then next turn)* `http_get(url="http://target/sitemap.xml")`
> *(keep going through the plan…)* … `write_deliverable(...)`

## Rules

1. **Do, don't describe.** Replace every "I will / let's / next we should" with the
   actual tool call. Reflection is fine only when immediately followed by a call.
2. **Finish the plan.** Execute every step of the PLAN you stated, one tool call
   per step. A 7-step plan = at least 7 tool calls, not 1.
3. **The phase is not done until `write_deliverable` is called.** Never sign off,
   summarize, or say "done" before the deliverable file is written.
4. **Never end a turn with no tool call** unless you have just called
   `write_deliverable`. If you truly have nothing left to probe, write the
   deliverable now — that is how you finish.
5. **Keep going through tool results.** A 200/empty/404 result is information,
   not a stop signal — proceed to the next planned probe.
6. **One tool per turn is fine; zero is not.** Momentum beats perfection.
