rule Trojan_Win64_Strab_A_2147833041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Strab.A!MTB"
        threat_id = "2147833041"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 89 c0 41 f7 ea 44 01 c2 c1 fa 05 44 89 c0 c1 f8 1f 29 c2 6b d2 ?? 44 89 c0 29 d0 48 63 d0 48 8b 0d ?? ?? ?? ?? 0f b6 14 11 42 32 94 04 ?? ?? ?? ?? 43 88 14 01 49 83 c0 01 4d 39 d8 75 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Strab_ARA_2147852902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Strab.ARA!MTB"
        threat_id = "2147852902"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 44 24 30 89 04 24 8b 44 24 30 ff c8 89 44 24 30 83 3c 24 00 74 2b 48 8b 44 24 20 48 8b 4c 24 28 0f b6 09 88 08 48 8b 44 24 20 48 ff c0 48 89 44 24 20 48 8b 44 24 28 48 ff c0 48 89 44 24 28 eb be}  //weight: 2, accuracy: High
        $x_2_2 = "\\ddvsm\\0804_161426\\cmd\\s\\out\\binaries\\amd64ret\\bin\\amd64\\Blend.pdb" ascii //weight: 2
        $x_1_3 = "GetClipboardFormatNameW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Strab_ASB_2147927969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Strab.ASB!MTB"
        threat_id = "2147927969"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {33 c0 48 8d 4d a0 48 89 45 04 89 45 0c 48 8d 05 ?? ?? ?? ?? 0f 11 45 b4 0f 11 45 a4 48 89 45 b0 48 8d 85 f0 00 00 00 0f 11 45 c4 48 89 45 b8 0f 11 45 d4}  //weight: 3, accuracy: Low
        $x_2_2 = {48 8d 0d c3 c2 01 00 ff 15 ?? ?? ?? ?? 33 c9 ff 15}  //weight: 2, accuracy: Low
        $x_1_3 = "\\danie\\source\\repos\\noconsole\\x64\\Release\\noconsole.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Strab_GZK_2147942726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Strab.GZK!MTB"
        threat_id = "2147942726"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {b2 30 1b 36 e4 bc 33 12 00 ab ?? ?? ?? ?? c6 f8 c1 fe 33 b6 ?? ?? ?? ?? f2 00 ee}  //weight: 5, accuracy: Low
        $x_5_2 = {2e 74 68 65 6d 69 64 61 00 e0 2e 00 00 10 16 00 00 00 00 00 00 40 14 00 00 00 00 00 00 00 00 00 00 00 00 00 60 00 00 e0 2e 62 6f 6f 74 00 00 00 00 dc 1c 00 00 f0 44 00 00 dc 1c 00 00 40 14}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

