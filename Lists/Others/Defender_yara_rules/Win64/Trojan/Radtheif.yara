rule Trojan_Win64_Radtheif_AHB_2147952970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Radtheif.AHB!MTB"
        threat_id = "2147952970"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Radtheif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {4c 8b 94 24 f0 00 00 00 4c 8b 9c 24 d8 00 00 00 44 0f b6 64 24 43 48 89 c6 48 89 cb 48 8b 44 24 50 48 8b 4c 24 60 e9}  //weight: 20, accuracy: High
        $x_30_2 = {48 8d 34 d9 48 8b 38 48 89 3c 30 48 ff c3 48 8d 72 ff 48 39 f3 7c}  //weight: 30, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Radtheif_AHC_2147953575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Radtheif.AHC!MTB"
        threat_id = "2147953575"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Radtheif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {89 fa 48 89 f7 49 89 ca 0f b6 b4 24 46 01 00 00 4c 89 c9 4c 8b 8c 24 f0 1c 00 00}  //weight: 20, accuracy: High
        $x_30_2 = {48 c1 c1 11 41 bb ef be ad de 4c 31 d9 41 bc be ba fe ca 49 0f af cc ba ed fe ce fa}  //weight: 30, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Radtheif_AHD_2147955871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Radtheif.AHD!MTB"
        threat_id = "2147955871"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Radtheif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {48 8b 94 24 90 00 00 00 48 ff c2 48 8b 44 24 58 48 8b 8c 24 50 01 00 00 48 8b 5c 24 50 0f 1f 40 ?? 48 83 fa}  //weight: 30, accuracy: Low
        $x_20_2 = {48 f7 ea 48 01 f2 48 c1 fa ?? 48 29 da 48 8d 14 92 48 c1 e2 ?? 48 29 d6 48 39 f1 0f}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Radtheif_AHE_2147956037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Radtheif.AHE!MTB"
        threat_id = "2147956037"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Radtheif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 8b 4c 24 20 f2 0f 10 41 ?? 48 8b 54 24 28 f2 0f 10 4a ?? 66 0f 2e c8 75}  //weight: 20, accuracy: Low
        $x_30_2 = {0f b6 94 01 ?? ?? 00 00 48 8d 59 d9 48 f7 db 0f b6 9c 03 ?? ?? 00 00 01 da 88 94 ?? ?? 01 00 00 48 ff c1 48 83 f9}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Radtheif_AHF_2147956389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Radtheif.AHF!MTB"
        threat_id = "2147956389"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Radtheif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {08 99 f6 42 d4 95 b7 ?? 87 17 a5 93 44 33 5b 0c 7f fb}  //weight: 30, accuracy: Low
        $x_20_2 = {f2 52 29 45 ?? a5 95 f6 37 a6 b8}  //weight: 20, accuracy: Low
        $x_10_3 = {51 65 ee 0a 3a 5d 93 6c 53 2d}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

