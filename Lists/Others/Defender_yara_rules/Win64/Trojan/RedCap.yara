rule Trojan_Win64_RedCap_ARA_2147897875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RedCap.ARA!MTB"
        threat_id = "2147897875"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RedCap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "1BlueDashUpdate.cmd" ascii //weight: 2
        $x_2_2 = "DecryptFileA" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RedCap_MKC_2147944544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RedCap.MKC!MTB"
        threat_id = "2147944544"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RedCap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 e7 8b c7 2b c2 d1 e8 03 c2 c1 e8 05 0f b7 c0 6b c8 38 0f b7 c7 41 03 fe 66 2b c1 66 41 03 c5 66 31 06 48 8d 76 ?? 83 ff 0b 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RedCap_MK_2147956187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RedCap.MK!MTB"
        threat_id = "2147956187"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RedCap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {48 c1 c0 2f 48 8d 14 89 48 31 d0 48 8d 1c 40 48 c1 e3 03 48 8d 1c 4b 48 89 de 48 c1 eb 35 48 31 f3 48 01 da 48 89 d3 48 c1 ea 29 48 31 da}  //weight: 15, accuracy: High
        $x_10_2 = {48 8d 14 52 48 8d 1c 49 48 8d 1c 59 48 8d 14 53 48 89 d3 48 c1 ea 1d 48 31 da 48 8d 14 d2 48 8d 59 01 48 8d 04 ca 48 89 d9 0f 1f 44}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RedCap_LMA_2147959143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RedCap.LMA!MTB"
        threat_id = "2147959143"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RedCap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {0f 86 d9 00 00 00 55 48 89 e5 48 83 ec 40 66 44 0f d6 7c 24 38 c6 44 24 17 00 44 0f 11 7c 24 28 31 db 89 c1 b8 01 00 00 00}  //weight: 20, accuracy: High
        $x_10_2 = {49 3b 66 10 0f 86 d9 00 00 00 55 48 89 e5 48 83 ec 40 66 44 0f d6 7c 24 38 c6 44 24 17 00 44 0f 11 7c 24 28 31 db 89 c1 b8 01 00 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

