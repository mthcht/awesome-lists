rule Trojan_Win32_FatalRat_RPY_2147898755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FatalRat.RPY!MTB"
        threat_id = "2147898755"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FatalRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 d8 1b c0 23 c6 68 a9 40 00 00 50 8d 4d d8 ff d7 85 c0 74 c3 6a 00 6a 04 8d 45 ec c7 45 ec 00 00 00 00 50 8d 4d d8 ff d3 85 c0 7e ab}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FatalRat_AFR_2147899018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FatalRat.AFR!MTB"
        threat_id = "2147899018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FatalRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 dc 33 36 30 74 c7 45 e0 72 61 79 2e 66 c7 45 e4 65 78 c7 45 c0 41 44 56 41 c7 45 c4 50 49 33 32 c7 45 c8 2e 64 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

