rule Trojan_Win64_Stealc_RPX_2147894330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealc.RPX!MTB"
        threat_id = "2147894330"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 10 00 00 77 47 00 00 f8 ?? 19 00 77 47 00 00 98 47 00 00 1c ?? 19 00 98 47 00 00 b9 47 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealc_GA_2147939347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealc.GA!MTB"
        threat_id = "2147939347"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b7 c8 81 e9 19 04 00 00 74 14 83 e9 09 74 0f 83 e9 01 74 0a 83 e9 1c 74 05 83 f9 04 75 08}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealc_GB_2147939348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealc.GB!MTB"
        threat_id = "2147939348"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 c1 42 8a 0c 08 32 0c 32 48 8d 55 ?? 88 4d ?? 49 8b ce e8 ?? ?? ?? ?? 48 ff c6 49 3b 75 ?? 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealc_DN_2147959767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealc.DN!MTB"
        threat_id = "2147959767"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 55 d8 48 8b 45 f0 48 01 d0 0f b6 10 48 8b 4d d8 48 8b 45 f0 48 01 c8 83 f2 29 88 10 50 51 59 58 48 83 45 f0 01 48 8b 45 f0 48 3b 45 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealc_ZZ_2147960628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealc.ZZ"
        threat_id = "2147960628"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {48 8b ec 48 83 ec ?? 48 8d 15 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? 0f 57 c0}  //weight: 10, accuracy: Low
        $x_10_3 = {4c 8b c0 48 8d 15 ?? ?? ?? ?? 48 8d 4d c0 e8 ?? ?? ?? ?? 48 8d 55 c0 48 8d 4d e0 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealc_YGB_2147963515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealc.YGB!MTB"
        threat_id = "2147963515"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SJUF4I8aggQmguiC9f5d/wXGSw7mctXYuKTq1G54R/47I7tJq74HM2UOAYln6b/Ed7q78e9o6ZuXJ0CTlkH" ascii //weight: 1
        $x_1_2 = "Go build ID:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealc_ZY_2147965833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealc.ZY"
        threat_id = "2147965833"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {48 8d 54 24 28 48 8d 4d 98 e8 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 0f b7 c8 81 e9 19 04 00 00 74 14 83 e9 09 74 0f 83 e9 01 74 0a 83 e9 1c 74 05 83 f9 04 75 08 33 c9 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealc_EM_2147967978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealc.EM!MTB"
        threat_id = "2147967978"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 8b 54 24 08 41 89 d0 41 81 f0 b3 00 00 00 83 e2 4c 01 d2 44 29 c2 88 54 0c 04}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

