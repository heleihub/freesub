#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线解析/归一化/配置合法性回归测试。
覆盖 URI、Base64、Clash/Mihomo YAML、sing-box JSON，以及关键分类逻辑。
"""
import base64
import json
import os
import subprocess
import sys
import tempfile

import yaml

import main_v2 as mv

SB = mv.SINGBOX_BIN + (".exe" if os.name == "nt" else "")
FAIL = []

UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

SAMPLES = {
    "vless_reality": f"vless://{UUID}@example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=0123abcd&type=tcp#Reality",
    "vmess_ws": "vmess://" + base64.b64encode(json.dumps({
        "v":"2","ps":"VMess","add":"vm.example.com","port":"443","id":UUID,
        "aid":"0","scy":"auto","net":"ws","type":"none","host":"vm.example.com",
        "path":"/ws","tls":"tls","sni":"vm.example.com"}).encode()).decode(),
    "trojan": "trojan://pass%40word@example.com:443?sni=www.example.com&allowInsecure=1&type=tcp#Trojan",
    "ss": "ss://aes-256-gcm:cGFzc3dvcmQ%3D@ss.example.com:8388#SS",
    "hy2": "hysteria2://pass123@hy2.example.com:443?sni=hy2.example.com&insecure=1&obfs=salamander&obfs-password=pw#HY2",
    "tuic": f"tuic://{UUID}:pass123@tuic.example.com:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=tuic.example.com&allow_insecure=1#TUIC",
    "anytls": "anytls://pass123@anytls.example.com:443?sni=anytls.example.com&insecure=1#AnyTLS",
    "ssh": "ssh://user:pass@example.com:22#SSH",
    "vless_ipv6": f"vless://{UUID}@[2001:db8::1]:443?security=tls&sni=v6.example.com&type=tcp#IPv6",
}

CLASH = {
    "proxies": [
        {"name":"clash-vless-reality","type":"vless","server":"v.example.com","port":443,"uuid":UUID,
         "network":"tcp","tls":True,"servername":"www.example.com","client-fingerprint":"chrome",
         "reality-opts":{"public-key":"SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc","short-id":"0123abcd"},
         "flow":"xtls-rprx-vision"},
        {"name":"clash-vmess-ws","type":"vmess","server":"m.example.com","port":443,"uuid":UUID,"alterId":0,
         "cipher":"auto","tls":True,"servername":"m.example.com","network":"ws","ws-opts":{"path":"/ws","headers":{"Host":"m.example.com"}}},
        {"name":"clash-trojan","type":"trojan","server":"t.example.com","port":443,"password":"pass","sni":"t.example.com","network":"grpc","grpc-opts":{"grpc-service-name":"svc"}},
        {"name":"clash-ss","type":"ss","server":"s.example.com","port":8388,"cipher":"aes-256-gcm","password":"pass"},
        {"name":"clash-hy2","type":"hysteria2","server":"h.example.com","port":443,"password":"pass","sni":"h.example.com","ports":"443,2087-2097","obfs":"salamander","obfs-password":"pw"},
        {"name":"clash-tuic","type":"tuic","server":"u.example.com","port":443,"uuid":UUID,"password":"pass","sni":"u.example.com","alpn":["h3"]},
        {"name":"clash-anytls","type":"anytls","server":"a.example.com","port":443,"password":"pass","sni":"a.example.com"},
        {"name":"clash-ssh","type":"ssh","server":"ssh.example.com","port":22,"username":"user","password":"pass"},
    ]
}

SINGBOX = {
    "outbounds": [
        {"type":"vless","tag":"sb-vless","server":"v.example.com","server_port":443,"uuid":UUID,
         "flow":"xtls-rprx-vision","tls":{"enabled":True,"server_name":"www.example.com",
         "utls":{"enabled":True,"fingerprint":"chrome"},"reality":{"enabled":True,"public_key":"SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc","short_id":"0123abcd"}}},
        {"type":"hysteria2","tag":"sb-hy2","server":"h.example.com","server_port":443,"password":"pass",
         "tls":{"enabled":True,"server_name":"h.example.com"}},
        {"type":"tuic","tag":"sb-tuic","server":"u.example.com","server_port":443,"uuid":UUID,"password":"pass",
         "congestion_control":"bbr","udp_relay_mode":"native","tls":{"enabled":True,"server_name":"u.example.com","alpn":["h3"]}},
        {"type":"shadowsocks","tag":"sb-ss","server":"s.example.com","server_port":8388,"method":"aes-256-gcm","password":"pass"},
    ]
}


def check_uri(name, uri):
    try:
        parsed = mv.parse_node_uri(uri)
        assert parsed, "parse returned None"
        ob, server, port, proto = parsed
        assert server and port > 0 and proto == ob["type"]
        return ob
    except Exception as e:
        FAIL.append(f"{name}: {e}")
        return None


def main():
    print("=" * 72)
    print("1) URI / Base64 解析")
    print("=" * 72)
    for name, uri in SAMPLES.items():
        ob = check_uri(name, uri)
        print(f"  {'OK' if ob else 'FAIL'} {name}: {ob.get('type') if ob else '-'}")

    print("\n" + "=" * 72)
    print("2) Clash / Mihomo YAML 解析")
    print("=" * 72)
    clash_text = yaml.safe_dump(CLASH, allow_unicode=True, sort_keys=False)
    obs = mv.extract_outbounds_from_structured(clash_text)
    print(f"  解析 {len(obs)}/{len(CLASH['proxies'])} 个 proxy")
    if len(obs) != len(CLASH["proxies"]): FAIL.append("Clash structured parse count mismatch")
    wrapped = mv.extract_nodes_from_text(clash_text)
    print(f"  sbnode 包装: {len(wrapped)}")
    if len(wrapped) != len(obs): FAIL.append("Clash sbnode wrapping mismatch")

    print("\n" + "=" * 72)
    print("3) sing-box JSON 解析")
    print("=" * 72)
    sb_text = json.dumps(SINGBOX)
    obs = mv.extract_outbounds_from_structured(sb_text)
    print(f"  解析 {len(obs)}/{len(SINGBOX['outbounds'])} 个 outbound")
    if len(obs) != len(SINGBOX["outbounds"]): FAIL.append("sing-box structured parse count mismatch")

    print("\n" + "=" * 72)
    print("4) Base64 包装的 Clash / sing-box")
    print("=" * 72)
    for name, text in (("clash", clash_text), ("singbox", sb_text)):
        encoded = base64.urlsafe_b64encode(text.encode()).decode()
        got = mv.extract_nodes_from_text(encoded)
        expected = len(CLASH["proxies"]) if name == "clash" else len(SINGBOX["outbounds"])
        print(f"  {name}: {len(got)}/{expected}")
        if len(got) != expected: FAIL.append(f"base64 {name} mismatch")

    print("\n" + "=" * 72)
    print("5) 关键网络分类离线逻辑")
    print("=" * 72)
    cases = [
        ("104.16.1.1", 13335, "Cloudflare, Inc.", "cdn"),
        ("8.8.8.8", 15169, "Google LLC", "cdn"),
        ("211.72.35.1", 3462, "Chunghwa Telecom", "residential"),
        ("23.94.10.1", 36352, "ColoCrossing", "datacenter"),
    ]
    for ip, asn, org, expect in cases:
        got, conf = mv.classify_network_type(ip, None, asn, org, None)
        print(f"  {ip} -> {got} conf={conf} (expect {expect})")
        if got != expect: FAIL.append(f"classify {ip}: got {got}, expect {expect}")

    if os.path.exists(SB):
        print("\n" + "=" * 72)
        print("6) sing-box check（仅检查配置结构，不联网）")
        print("=" * 72)
        sample_obs = []
        for uri in SAMPLES.values():
            ob = check_uri("sample", uri)
            if ob: sample_obs.append(ob)
        for ob in sample_obs + [mv.parse_clash_proxy(x) for x in CLASH["proxies"]]:
            if not ob: continue
            cfg = mv.build_test_config(ob, 53000 + (abs(hash(ob.get("tag","node"))) % 500))
            path = None
            try:
                with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
                    json.dump(cfg, f); path = f.name
                r = subprocess.run([SB, "check", "-c", path], capture_output=True, text=True, timeout=15)
                if r.returncode != 0:
                    err = (r.stderr or r.stdout or "").strip().splitlines()
                    FAIL.append(f"sing-box check {ob.get('tag')}: {(err[-1] if err else '?')[:120]}")
                    print(f"  FAIL {ob.get('tag')}")
                else:
                    print(f"  OK   {ob.get('tag')}")
            finally:
                if path and os.path.exists(path): os.remove(path)
    else:
        print("\n[SKIP] runtime/sing-box 不存在，跳过 check；CI 会先下载内核。")

    print("\n" + "=" * 72)
    if FAIL:
        print(f"失败 {len(FAIL)} 项:")
        for x in FAIL: print(" -", x)
        sys.exit(1)
    print("全部离线回归测试通过。")


if __name__ == "__main__":
    main()
