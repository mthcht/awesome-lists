rule Trojan_Win64_PermClaw_A_2147943820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PermClaw.A"
        threat_id = "2147943820"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PermClaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 24 48 8b ?? 24 ?? 0f be ?? ?? 0f b6 ?? ?? 33 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 48 30 b8 4d 4f 00 00 48 8b ?? 24 38 66 89 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

