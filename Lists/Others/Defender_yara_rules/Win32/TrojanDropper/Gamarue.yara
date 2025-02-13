rule TrojanDropper_Win32_Gamarue_A_2147679427_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Gamarue.gen!A"
        threat_id = "2147679427"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 ff 00 00 00 f7 f9 4e 00 56 01 4f 75 ec 53 6a 06 6a 02 53 53 68 00 00 00 40 8d 95 ?? ?? ff ff 52}  //weight: 1, accuracy: Low
        $x_1_2 = {74 09 80 34 30 ?? 40 3b c7 72 f7}  //weight: 1, accuracy: Low
        $x_1_3 = "\\Release\\ADropper.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_Win32_Gamarue_G_2147682167_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Gamarue.G"
        threat_id = "2147682167"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 38 80 e9 42 32 ca ff 44 24 ?? 88 0c 38 39 5c 24 ?? 72 e7}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 08 40 3a cb 75 f9 2b c2 8b c8 0f 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Gamarue_H_2147682245_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Gamarue.H"
        threat_id = "2147682245"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 31 89 45 ?? 8b 45 ?? 33 d2 f7 f7 66 8b 04 55 ?? ?? ?? ?? 66 89 04 71 85 f6 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 0c 30 80 e9 ?? 32 ca ff 44 24 ?? 88 0c 30 39 7c 24 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Gamarue_J_2147682678_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Gamarue.J"
        threat_id = "2147682678"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 49 00 6e 00 63 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8a 0c 38 f6 d1 80 c1 ?? 32 ca 88 0c 38 8b 85 ?? ?? ff ff 40 89 85 ?? ?? ff ff 3b 85 ?? ?? ff ff 72 de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

