rule Trojan_Win64_RevShell_NW_2147958943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RevShell.NW!MTB"
        threat_id = "2147958943"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RevShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 45 a0 48 8d 15 d9 36 00 00 48 89 c1 e8 06 18 00 00 48 85 c0 75 30 48 8d 45 a0 48 8d 15 c6 36 00 00 48 89 c1 e8 ee 17 00 00 48 85 c0 75 18 48 8d 45 a0 48 8d 15 b5 36 00 00 48 89 c1 e8 d6 17 00 00 48 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RevShell_JD_2147959654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RevShell.JD!MTB"
        threat_id = "2147959654"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RevShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 45 d0 48 89 44 24 48 48 8d 45 f0 48 89 44 24 40 48 c7 44 24 38 00 00 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 00 08 c7 44 24 20 01 00 00 00 48 8b 85 90 00 00 00 41 b9 00 00 00 00 41 b8 00 00 00 00 48 8d 15 a9 29 00 00 b9 00 00 00 00 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

