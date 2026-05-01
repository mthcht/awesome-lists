rule Trojan_Win64_FatalRAT_GZZ_2147944875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FatalRAT.GZZ!MTB"
        threat_id = "2147944875"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FatalRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {ff d3 c7 44 24 24 00 00 00 00 31 d2 89 d0 41 89 d0 8b 4c 24 24 41 c1 f8 02 83 e0 3f 41 0f af c0 44 6b c2 0d ff c2 44 31 c0 01 c8 81 fa f4 01 00 00 89 44 24 24}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_FatalRAT_NR_2147968206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FatalRAT.NR!MTB"
        threat_id = "2147968206"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FatalRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c7 45 30 43 00 3a 00 c7 45 34 2f 00 55 00 c7 45 38 73 00 65 00 c7 45 3c 72 00 73 00 c7 45 40 2f 00 50 00 c7 45 44 75 00 62 00 c7 45 48 6c 00 69 00}  //weight: 2, accuracy: High
        $x_1_2 = {c7 45 50 44 00 6f 00 c7 45 54 77 00 6e 00 c7 45 58 6c 00 6f 00 c7 45 5c 61 00 64 00 c7 45 60 73 00 2f 00 c7 45 64 74 00 70 00 c7 45 68 73 00 76 00 c7 45 6c 63 00 42 00 c7 45 70 61 00 73 00 c7 45 74 65 00 2e 00 c7 45 78 64 00 6c 00 c7 45 7c 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"Startup\" /t REG_SZ /d \"C:\\Users\\Public\\Downloads\\svchost.%s\" /f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

