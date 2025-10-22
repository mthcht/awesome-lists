rule Trojan_Win64_Rugmi_MKV_2147923016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rugmi.MKV!MTB"
        threat_id = "2147923016"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {d3 eb 41 33 da 41 2b da 89 d9 41 0f af c9 81 c1 80 00 00 00 c1 e9 08 81 f1 00 00 80 00 81 e9 00 00 80 00 8b d9 48 0f b6 4c ?? ?? d3 e3 2b 1a 89 1a 48 83 c2 04 48 83 c0 04 41 83 c0 01 45 3b c3 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rugmi_MV_2147935917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rugmi.MV!MTB"
        threat_id = "2147935917"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 ca c1 e2 ?? 31 ca 41 89 d0 41 c1 e8 ?? 41 31 d0 44 89 c1 c1 e1 ?? 44 31 c1 89 4c 05 ?? 48 83 c0 ?? 48 83 f8 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rugmi_HI_2147946531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rugmi.HI!MTB"
        threat_id = "2147946531"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {ff d0 48 89 c7 ?? 8b 05}  //weight: 20, accuracy: Low
        $x_20_2 = {ff d3 48 89 df ?? 8b 1d}  //weight: 20, accuracy: Low
        $x_20_3 = {ff d1 48 89 cf ?? 8b 0d}  //weight: 20, accuracy: Low
        $x_1_4 = {48 63 40 3c 8b 84 06 88 00 00 00 ?? 8b}  //weight: 1, accuracy: Low
        $x_1_5 = {48 63 5b 3c 8b 9c 1e 88 00 00 00 ?? 8b}  //weight: 1, accuracy: Low
        $x_1_6 = {48 63 49 3c 8b 8c 0e 88 00 00 00 ?? 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Rugmi_HJ_2147947077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rugmi.HJ!MTB"
        threat_id = "2147947077"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {00 31 c0 89 c2 66 83 3c ?? 00 06 00 (48|4c) 8b}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rugmi_HK_2147947439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rugmi.HK!MTB"
        threat_id = "2147947439"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 48 3c 49 ?? ?? 8b 7c ?? 2c [0-26] ff (d0|2d|d7)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rugmi_HL_2147947637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rugmi.HL!MTB"
        threat_id = "2147947637"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 00 00 00 44 8b ?? ?? 24 8b ?? 01 1c 07 00 48 63 48 3c 8b ?? 01 [0-255] 44 8b [0-255] 8b (0d|05|1d) [0-255] ff (d0|2d|d7)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rugmi_HN_2147948569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rugmi.HN!MTB"
        threat_id = "2147948569"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 44 24 40 48 8b 40 10 48 63 40 3c 48 8b 4c 24 40 48 03 41 10 48 89 44 24 28 48 8b 44 24 28 0f b7 40 18 25 00 02 00 00 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rugmi_YBH_2147950702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rugmi.YBH!MTB"
        threat_id = "2147950702"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 ec 30 48 8b 05 94 ab 0c 00 48 bb 32 a2 df 2d 99 2b 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {4c 0f be 37 41 b8 40 00 00 00 4c 03 f7 41 8b 4e 04 45 8b 7e 08 89 4d 77 41 8b d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rugmi_MZZ_2147955753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rugmi.MZZ!MTB"
        threat_id = "2147955753"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 f7 eb d1 fa 8b c2 c1 e8 1f 03 d0 8d 14 52 c1 e2 02 41 8b c3 2b c2 48 63 d0 48 8d 05 7a 94 06 00 8a 04 02 d2 e0 41 30 04 28 41 ff c3 49 ff c0 4c 3b c3 7c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

