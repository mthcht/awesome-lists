rule Trojan_Win64_Remus_C_2147967667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remus.C!MTB"
        threat_id = "2147967667"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {87 ff 0e 00 0f 10 05 ?? ?? ?? ?? 0f 29 44 24 ?? 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 ?? c7 44 24 ?? 00 00 00 00 8b 44 24 ?? 83 f8 14 77}  //weight: 5, accuracy: Low
        $x_5_2 = {8b 4c d1 04 4c 89 6c 24 ?? 0f 11 74 24 ?? 48 c7 44 24 ?? 00 00 00 08 48 c7 44 24 ?? 02 00 00 00 41 b9 04 00 00 00 ba 07 00 00 00 4c 8d 44 24 ?? e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Remus_DA_2147972599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remus.DA!MTB"
        threat_id = "2147972599"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b6 42 11 88 41 21 0f b6 42 12 88 41 22 0f b6 42 13 88 41 23 0f b6 42 14 88 41 24 0f b6 42 15 88 41 25 0f b6 42 16 88 41 26 0f b6 42 17 88 41 27 0f b6 42 18 88 41 28 0f b6 42 19 88 41 29 0f b6 42 1a 88 41 2a 0f b6 42 1b 88 41 2b 0f b6 42 1c 88 41 2c 0f b6 42 1d 88 41 2d 0f b6 42 1e 88 41 2e 0f b6 42 1f 88 41 2f 44 89 49 30 49 c1 e9 20 44 89 49 34 41 8b 00 89}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Remus_AX_2147972704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remus.AX!MTB"
        threat_id = "2147972704"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 48 85 c0 74 51 48 8b 48 18 48 85 c9 74 48 48 8b 51 20 48 83 c1 20 31 c0 48 39 ca 74 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Remus_PL_2147973221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remus.PL!MTB"
        threat_id = "2147973221"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 2c 48 63 c9 ff 44 24 2c 8b 54 24 2c 69 d2 d2 40 00 00 66 33 54 4c 30 66 89 54 4c 30 8b 4c 24 2c 83 f9 0d 72 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Remus_NYB_2147973236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remus.NYB!MTB"
        threat_id = "2147973236"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetClipboardData" ascii //weight: 1
        $x_1_2 = "OpenClipboard" ascii //weight: 1
        $x_1_3 = {b1 79 37 9e 41 0f af d1 41 81 f1 b1 79 37 1e}  //weight: 1, accuracy: High
        $x_2_4 = {d1 e8 41 83 e0 01 41 f7 d8 41 21 d0 41 31 c0 44 89 c0 d1 e8 41 83 e0 01 41 f7 d8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

