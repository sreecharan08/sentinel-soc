"""
Runs Stage 4 against three records shaped like your existing dashboard
fixtures (com.demo.expfixture / com.lumen.flashlightpro / the benign apps),
with no API key set -- so the LLM client falls back to the deterministic
mock and you can see the whole pipeline execute for free.

    python demo.py

Once you've activated Alibaba Model Studio, set the three STAGE4_LLM_*
env vars from llm_client.py's docstring and run this again -- same code,
real reasoning instead of the mock.
"""

from __future__ import annotations

from .active_lists import CorrelationWindow, JSONActiveLists
from .agent import analyze
from .llm_client import LLMClient
from .schema import AnalysisRecord, CertInfo, NativeLib, NetworkIOCs

SAMPLES = [
    AnalysisRecord(
        sample_id="sub-001", package_name="com.demo.expfixture",
        sha256="aaaa...fixture1", device_id="pixel-7-01",
        dangerous_permissions=["SEND_SMS", "READ_CONTACTS"],
        dynamic_behaviors=["beacon_detected", "sms_sent_silently", "contacts_exfil_attempt"],
        native_libs=[NativeLib("libcore.so", 7.8)],
        network=NetworkIOCs(urls=["http://185.220.101.9/beacon"]),
        cert=CertInfo(is_self_signed=True, issuer=None),
    ),
    AnalysisRecord(
        sample_id="sub-002", package_name="com.lumen.flashlightpro",
        sha256="bbbb...fixture2", device_id="galaxy-s23fe-01",
        dangerous_permissions=["CAMERA", "RECORD_AUDIO"],
        dynamic_behaviors=["camera_access_no_ui", "obfuscated_sdk_loaded"],
        native_libs=[NativeLib("adlib.so", 6.1)],
        network=NetworkIOCs(),
        cert=CertInfo(is_self_signed=False, issuer="Android Debug"),
    ),
    AnalysisRecord(
        sample_id="sub-003", package_name="org.opensource.weathernow",
        sha256="cccc...fixture3", device_id="pixel-8a-01",
        dangerous_permissions=[], dynamic_behaviors=[],
        native_libs=[], network=NetworkIOCs(), cert=CertInfo(),
    ),
]


def main():
    active_lists = JSONActiveLists(path="demo_active_lists.json")
    correlation = CorrelationWindow()
    llm = LLMClient()
    print(f"LLM backend: {'MOCK (no credentials set)' if llm.is_mock else llm.model}\n")

    for record in SAMPLES:
        verdict = analyze(record, active_lists, correlation, llm)
        print(f"=== {record.package_name} ===")
        print(f"  verdict:    {verdict.verdict}  (confidence {verdict.confidence})")
        print(f"  provider:   {verdict.provider}")
        print(f"  attck:      {verdict.attck}")
        print(f"  rationale:  {verdict.rationale}")
        if verdict.agentic_trace:
            print(f"  trace:")
            for step in verdict.agentic_trace:
                print(f"    - {step}")
        print()


if __name__ == "__main__":
    main()
