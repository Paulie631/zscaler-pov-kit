# Zscaler POV Kit plugin

Lets Claude run the Zscaler POV Kit for you: "start a POV for Acme with ZIA and ZPA", "run preflight", "what's left
for the customer?", "check status", "build the report", "propose a use case: marketing can't upload to Dropbox",
"hand over the POV".

Bundles a copy of the kit. Claude runs it on your own computer, so you need the Claude desktop app with access to your
computer, plus `uv`. Secrets are typed by you in the console or your own terminal, never in chat. Claude never
approves a change list, applies it, or tears a POV down without you saying so, and the customer's approval is always
needed before anything is written to their tenant.

Build it with `python tools/build_plugin.py` (writes `dist/zscaler-pov-kit.plugin`).
