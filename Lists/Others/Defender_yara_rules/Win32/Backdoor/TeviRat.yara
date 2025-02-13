rule Backdoor_Win32_TeviRat_GMD_2147853405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/TeviRat.GMD!MTB"
        threat_id = "2147853405"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "TeviRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {a1 98 15 27 01 89 35 bc 10 27 01 8b fe 38 18 74 ?? 8b f8 8d 45 f8 50}  //weight: 10, accuracy: Low
        $x_10_2 = {83 c4 14 48 89 35 a4 10 27 01 5f 5e a3 a0 10 27 01}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_TeviRat_HNA_2147910586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/TeviRat.HNA!MTB"
        threat_id = "2147910586"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "TeviRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 75 25 63 25 63 25 63 25 63 25 63 25 63 2e 75 61 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 76 25 63 25 63 25 63 25 63 25 63 25 63 2e 72 75 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 77 25 63 25 63 25 63 25 63 25 63 25 63 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 78 25 63 25 63 25 63 25 63 25 63 25 63 2e 6e 65 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 79 25 63 25 63 25 63 25 63 25 63 25 63 2e 69 6e 66 6f 00}  //weight: 1, accuracy: High
        $x_1_6 = {7a 25 63 25 63 25 63 25 63 25 63 25 63 2e 75 61 [0-64] 48 6f 73 74 3a 20 25 73 0d 0a 0d 0a 00 00 00 00 [0-32] 63 00 00 00 63 6f 6e 6e 65 63 74 00 64 69 73 63 6f 6e 6e 65 63 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_TeviRat_HNB_2147910595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/TeviRat.HNB!MTB"
        threat_id = "2147910595"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "TeviRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 44 0d d4 8b 55 08 32 c2 32 04 3a 41 83 f9 10 88 04 3a 75 02 33 c9 ff 45 08 39 75 08 72 e1}  //weight: 1, accuracy: High
        $x_1_2 = {03 01 8b 55 08 03 c2 8b 55 f8 01 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

