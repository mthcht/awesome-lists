rule Trojan_Win32_Krucky_NAB_2147926849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Krucky.NAB!MTB"
        threat_id = "2147926849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Krucky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "kkrunchyS" ascii //weight: 2
        $x_1_2 = {c1 f8 02 66 ab 80 c4 08 c1 e8 04 83 ca ff 29 c2 0f b6 c0 0f b6 d2 22 84 1b 9c ad 9c 00 22 94 1b 9b ad 9c 00 29 d0 66 ab}  //weight: 1, accuracy: High
        $x_1_3 = {31 c0 ac 89 c3 ac 40 43 01 c3 c1 e0 10 99 f7 f3 ab e2 ed b5 02}  //weight: 1, accuracy: High
        $x_1_4 = {83 f3 01 8a 24 1f 80 fc 02 76 0f 0f b6 c4 8b 04 85 97 a9 9c 00 c1 e0 02 fe cc 83 f3 01 8a 04 1f 40 3c 28 76 02 b0 28 f6 c3 01 74 02 86 c4 57 89 ca f2 66 af 74 03 42 66 af f7 d1 01 d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Krucky_NAC_2147926934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Krucky.NAC!MTB"
        threat_id = "2147926934"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Krucky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "kkrunchy" ascii //weight: 2
        $x_1_2 = {0f 6f 1e 0f 6f 17 0f ed db 0f e5 d8 0f ed d9 0f 71 e3 01 0f ed d3 0f 7f 17 83 c6 08 83 c7 08 e2 df}  //weight: 1, accuracy: High
        $x_1_3 = {c1 f8 02 66 ab 80 c4 08 c1 e8 04 83 ca ff 29 c2 0f b6 c0 0f b6 d2 22 84 1b 10 ee 9c 00 22 94 1b 0f ee 9c 00 29 d0 66 ab 83 fb 01}  //weight: 1, accuracy: High
        $x_1_4 = {83 f3 01 8a 24 1f 80 fc 02 76 0f 0f b6 c4 8b 04 85 0b ea 9c 00 c1 e0 02 fe cc 83 f3 01 8a 04 1f 40 3c 28 76 02 b0 28 f6 c3 01 74 02 86 c4 57 89 ca f2 66 af 74 03 42 66 af f7 d1 01 d1 66 89 47 fe 88 0e 46 89 d1 5f 43 80 ff 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Krucky_AHB_2147948332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Krucky.AHB!MTB"
        threat_id = "2147948332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Krucky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b9 19 00 00 00 33 c0 8a 90 ?? ?? ?? ?? 32 d1 41 81 e1 ff 00 00 80 88 54 05 e4 79 ?? 49 81 c9 00 ff ff ff 41 40 83 f8 0c 7c}  //weight: 10, accuracy: Low
        $x_5_2 = {89 45 d4 89 45 d8 89 45 dc 88 45 e0 89 45 e4 89 45 e8 89 45 ec 88 45 f0 a1 ?? ?? ?? ?? 8b 11 8b 52 08 05 b8 00 00 00 50 ff d2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

