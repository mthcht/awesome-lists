rule Trojan_Win64_Clipbanker_MA_2147839262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Clipbanker.MA!MTB"
        threat_id = "2147839262"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Clipbanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 89 ee 48 81 c6 3f 01 00 00 48 8b 36 48 81 c6 09 00 00 00 4c 0f b7 2e 48 89 e8 48 05 2f 00 00 00 44 03 28 49 89 ef 49 81 c7 6f 01 00 00 45 03 2f 49 89 ef 49 81 c7 2f 00 00 00 45 21 2f 48 89 ea 48 81 c2 dd 00 00 00 48 89 eb 48 81 c3 2c 00 00 00 40 8a 3b}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Clipbanker_CCHT_2147903450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Clipbanker.CCHT!MTB"
        threat_id = "2147903450"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Clipbanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? b9 01 00 00 00 ff 15 ?? ?? ?? ?? 48 8b f8 48 8b c8 ff 15 ?? ?? ?? ?? 48 8b d8 48 c7 c6 ff ff ff ff 4c 8b c6 49 ff c0 42 80 3c 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Clipbanker_AHC_2147948331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Clipbanker.AHC!MTB"
        threat_id = "2147948331"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Clipbanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8b 85 90 01 00 00 48 63 48 04 8b c7 48 83 bc 0d d8 01 00 00 00 41 0f 45 c7 0b 84 0d a0 01 00 00 83 e0 15 83 c8 02 89 84 0d a0 01 00 00 23 84 0d a4 01 00 00 0f 85}  //weight: 5, accuracy: High
        $x_3_2 = {8b 45 d0 ff c0 89 44 24 28 48 89 4c 24 20 41 b9 01 00 00 00 45 33 c0 48 8d 15 ?? ?? ?? ?? 48 8b 4c 24 50 ff 15}  //weight: 3, accuracy: Low
        $x_2_3 = "cosmos1depk54cuajgkzea6zpgkq36tnjwdzv4afc3d27" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

