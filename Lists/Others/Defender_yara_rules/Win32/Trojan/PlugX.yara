rule Trojan_Win32_PlugX_RPQ_2147816305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PlugX.RPQ!MTB"
        threat_id = "2147816305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PlugX"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 1c 10 80 c3 fc 88 1c 10 40 3b c1 7c f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PlugX_2147844415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PlugX.psyN!MTB"
        threat_id = "2147844415"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PlugX"
        severity = "Critical"
        info = "psyN: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {83 ed 02 9c ff 34 24 68 6b 30 df 90 e8 fe 04 00 00 80 fe bd 66 0f a3 f8 e9 e3 ff ff ff}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PlugX_2147845843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PlugX.psyP!MTB"
        threat_id = "2147845843"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PlugX"
        severity = "Critical"
        info = "psyP: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {ff 96 28 9c 01 00 8b ae 30 9c 01 00 8d be 00 f0 ff ff bb 00 10 00 00 50 54 6a 04 53 57 ff d5 8d 87 d7 01 00 00 80 20 7f 80 60 28 7f 58 50 54 50 53 57 ff d5 58 61 8d 44 24 80 6a 00 39 c4 75 fa 83 ec 80 e9 4f c4 fe ff}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PlugX_RK_2147913406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PlugX.RK!MTB"
        threat_id = "2147913406"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PlugX"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ff b3 65 a1 ?? ?? ?? ?? c6 44 24 20 6c 85 c0 c6 44 24 21 73 c6 44 24 22 74 c6 44 24 23 72 c6 44 24 24 6c 88 5c 24 25 c6 44 24 26 6e c6 44 24 27 41 c6 44 24 28 00 75 ?? 88 44 24 1c a1 ?? ?? ?? ?? 85 c0 c6 44 24 14 6b 88 5c 24 15 c6 44 24 16 72 c6 44 24 17 6e 88 5c 24 18 c6 44 24 19 6c c6 44 24 1a 33 c6 44 24 1b 32 75 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PlugX_RKA_2147913407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PlugX.RKA!MTB"
        threat_id = "2147913407"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PlugX"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "345678912345678912345678912345678912345678912345678912345678912345678" ascii //weight: 1
        $x_1_2 = "SCRDLL" ascii //weight: 1
        $x_1_3 = "SRCDAT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PlugX_A_2147913410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PlugX.A!MTB"
        threat_id = "2147913410"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PlugX"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {56 ff 15 58 ?? 40 00 8b f0 b8 02 00 00 00 66 89 45 ec 0f b7 45 0c 50 ff 15 ?? ?? 40 00 66 89 45 ee 8b 46 0c 6a 10 8b 00 8b 00 89 45 f0 8d 45 ec 50 ff 77 08 ff 15 70 ?? 40 00 83 f8 ff 75 ?? ff 77 0c ff d3 68 e8 03 00 00 ff 77 0c ff 15 08 ?? 40 00 8b 75 e8 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PlugX_KK_2147957307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PlugX.KK!MTB"
        threat_id = "2147957307"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PlugX"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {8b 45 08 50 8d 8d ?? ?? ff ff 8b 55 f8 8b c6 8b 38 ff 57 ?? 8b 85 70 fe ff ff e8 ?? ?? ff ff 59 ff 45 f8 ff 4d f4}  //weight: 20, accuracy: Low
        $x_10_2 = "1VXpYjXX65Rhsef1SA53On1UiF1TXv3YscUS" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

