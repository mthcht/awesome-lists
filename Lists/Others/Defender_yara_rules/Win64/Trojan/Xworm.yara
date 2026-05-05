rule Trojan_Win64_Xworm_PGXS_2147948876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Xworm.PGXS!MTB"
        threat_id = "2147948876"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Xworm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c6 84 24 31 5a 00 00 68 c6 84 24 32 5a 00 00 43 c6 84 24 33 5a 00 00 33 c6 84 24 34 5a 00 00 34 c6 84 24 35 5a 00 00 68 c6 84 24 36 5a 00 00 78 c6 84 24 37 5a 00 00 51 c6 84 24 38 5a 00 00 72 c6 84 24 39 5a 00 00 4b c6 84 24 3a 5a 00 00 58 c6 84 24 3b 5a 00 00 34}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Xworm_AXW_2147952319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Xworm.AXW!MTB"
        threat_id = "2147952319"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Xworm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 69 c1 65 89 07 6c 41 81 f0 b9 79 37 9e 41 c1 c8 13 44 03 c0 41 8b c0 c1 e8 10 42 32 44 09 04 42 88 04 0a 49 ff c1 49 83 f9 13}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Xworm_AXW_2147952319_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Xworm.AXW!MTB"
        threat_id = "2147952319"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Xworm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b da 8b f9 48 8d 0d 02 71 03 00 ff 15 ?? ?? ?? ?? 48 8d 15 8d 5d 03 00 48 8b c8 ff 15 ?? ?? ?? ?? 48 85 c0 48 0f 44 05 91 92 03 00 48 8b d3 8b cf}  //weight: 2, accuracy: Low
        $x_3_2 = {48 8d 0d 9b 61 03 00 ff 15 ?? ?? ?? ?? 48 8b c8 48 8d 15 eb 4d 03 00 48 8b d8 ff 15 ?? ?? ?? ?? 48 8d 15 83 4a 03 00 48 8b cb 48 89 05 89 1b 04 00 ff 15 ?? ?? ?? ?? 48 8d 15 fc 4d 03 00 48 8b cb 48 89 05 7a 1b 04 00 ff 15}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Xworm_PGXO_2147958281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Xworm.PGXO!MTB"
        threat_id = "2147958281"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Xworm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4c 89 c2 44 89 c1 83 e2 ?? 83 e1 ?? 8b 14 97 c1 e1 ?? d3 ea 42 30 14 00 48 8b 06 49 83 c0 ?? 48 8b 56 ?? 48 29 c2 44 39 c2 7f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Xworm_PGXR_2147966996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Xworm.PGXR!MTB"
        threat_id = "2147966996"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Xworm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 c9 49 03 d9 8a 44 0d d8 30 04 0b 48 ff c1 49 3b c8 72}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Xworm_AZZ_2147968495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Xworm.AZZ!MTB"
        threat_id = "2147968495"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Xworm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {c6 84 24 ff 0d 00 00 44 c6 84 24 00 0e 00 00 24 c6 84 24 01 0e 00 00 50 c6 84 24 02 0e 00 00 48 c6 84 24 03 0e 00 00 89 c6 84 24 04 0e 00 00 44 c6 84 24 05 0e 00 00 24 c6 84 24 06 0e 00 00 40 c6 84 24 07 0e 00 00 48 c6 84 24 08 0e 00 00 8d c6 84 24 09 0e 00 00 45 c6 84 24 0a 0e 00 00 f0 c6 84 24 0b 0e 00 00 48 c6 84 24 0c 0e 00 00 89 c6 84 24 0d 0e 00 00 44 c6 84 24 0e 0e 00 00 24 c6 84 24 0f 0e 00 00 48}  //weight: 3, accuracy: High
        $x_1_2 = "C:\\OSD\\XR\\cmd.exe" ascii //weight: 1
        $x_1_3 = "UAC BYPASS DEBUGGER STARTING" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

