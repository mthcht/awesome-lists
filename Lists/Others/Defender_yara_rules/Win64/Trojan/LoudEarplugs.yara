rule Trojan_Win64_LoudEarplugs_C_2147949384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LoudEarplugs.C!dha"
        threat_id = "2147949384"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LoudEarplugs"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "EFDC5AF4-*&@233D<>(&-432c.?_+-AB$~87-3ECBNEBXRT&65FEK+*#E2NM:50!~76-?*" ascii //weight: 1
        $x_1_2 = {8a 00 30 04 3e e8 ?? ?? ?? ?? 8b c8 33 d2 8d 43 01 46 f7 f1 8b da 3b 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_LoudEarplugs_B_2147949385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LoudEarplugs.B!dha"
        threat_id = "2147949385"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LoudEarplugs"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bc b4 e7 b1 e6 b7 b4 e7 bd b1 b4 b7 b3 b2 e0 e4 b6 e0 bc e7 e4 e7 bc b7 b6 bc b3 b6 b4 bd e0 b2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LoudEarplugs_B_2147949385_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LoudEarplugs.B!dha"
        threat_id = "2147949385"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LoudEarplugs"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {22 81 50 79 c7 85 ?? ?? ?? ?? 4c 52 28 e9 c7 85 ?? ?? ?? ?? ab b7 ed 09 c7 85 ?? ?? ?? ?? bf ac 98 86 c7 85 ?? ?? ?? ?? 65 a0 e8 70 c7 85 ?? ?? ?? ?? ef e0 68 f2 c7 85 ?? ?? ?? ?? cc e1 6f 11 c7 85 ?? ?? ?? ?? b0 5c 15 7a c7 85 ?? ?? ?? ?? 49 1b ee 19 c7 85 ?? ?? ?? ?? b9 f4 eb 2a c7 85 ?? ?? ?? ?? e7 fa fd a3 c7 85 ?? ?? ?? ?? 6c 48 89 3c c7 85 ?? ?? ?? ?? d0 35 42 4d c7 85 ?? ?? ?? ?? 3f 19 6a df c7 85 ?? ?? ?? ?? d4 2e 99 5b c7 85 ?? ?? ?? ?? 8c fb ce 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

