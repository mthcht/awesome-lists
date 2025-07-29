rule Trojan_Win64_DarkGate_CCBP_2147891779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DarkGate.CCBP!MTB"
        threat_id = "2147891779"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 b8 69 73 6d 2e 31 5c 63 69 48 ba 6c 62 75 70 5c 73 72 65 48 89 44 24 20 48 8d 4c 24 20 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 54 24 28 48 ba ?? ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 30 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 54}  //weight: 1, accuracy: Low
        $x_1_2 = {24 38 48 ba ?? ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 40 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 54 24 48 48 ba ?? ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 50 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 54 24 58 48 ba ?? ?? ?? ?? ?? ?? ?? ?? 48 89}  //weight: 1, accuracy: Low
        $x_1_3 = {44 24 60 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 54 24 68 48 ba ?? ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 70 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 54 24 78 48 ba ?? ?? ?? ?? ?? ?? ?? ?? 48 89 84 24 80 00 00 00 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 94 24 88 00 00 00 48 ba ?? ?? ?? ?? ?? ?? ?? ?? 48 89 84 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DarkGate_MZY_2147919514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DarkGate.MZY!MTB"
        threat_id = "2147919514"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {45 03 cd 49 8b c8 49 f7 e0 48 2b ca 48 d1 e9 48 03 ca 48 c1 e9 04 48 6b c1 19 4c 2b c0 42 8a 44 04 ?? 43 32 04 13 41 88 02 4d 03 d5 44 3b ce 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DarkGate_GVD_2147947742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DarkGate.GVD!MTB"
        threat_id = "2147947742"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 63 d0 0f b6 0c 32 41 88 0c 31 44 88 14 32 41 0f b6 14 31 49 03 d2 0f b6 ca 0f b6 0c 31 41 30 0b 49 ff c3 48 83 eb 01 75 a3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

