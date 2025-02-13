rule TrojanDownloader_Win32_Drixed_B_2147690025_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Drixed.B"
        threat_id = "2147690025"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Drixed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 5c 03 10 81 3b ef be ad de 74}  //weight: 1, accuracy: High
        $x_1_2 = {65 64 67 00 2e 74 6d 70 00 00 00 00 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = {00 2e 73 64 61 74 61 00 00 20 00 00 00 2e 4b 42 00 44 69 73 70 6c 61 79 4e 61 6d 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Drixed_B_2147690025_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Drixed.B"
        threat_id = "2147690025"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Drixed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 73 64 61 74 61 00 00 20 00 00 00 3f 00 00 00 2e 4b 42 00 44 69 73 70 6c 61 79 4e 61 6d 65 04 00 5f 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {81 3b ef be ad de 74 ?? eb}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 40 08 f7 28 9e 50 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Drixed_D_2147691035_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Drixed.D"
        threat_id = "2147691035"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Drixed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 40 08 f7 28 9e 50}  //weight: 2, accuracy: High
        $x_2_2 = {ef be ad de eb 01 00 02 01 01 bf be}  //weight: 2, accuracy: Low
        $x_2_3 = {8d 78 10 8b 45 ?? 8b 55 ?? 33 07 33 57 04 83 65 0c 00}  //weight: 2, accuracy: Low
        $x_1_4 = {52 00 65 00 64 00 69 00 72 00 65 00 63 00 74 00 45 00 58 00 45 00 [0-10] 25 00 4c 00 4f 00 43 00 41 00 4c 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 25 00 4c 00 6f 00 77 00 5c 00 ?? ?? ?? ?? ?? ?? 2e 00 62 00 61 00 74 00}  //weight: 1, accuracy: Low
        $x_1_5 = "S:\\Work\\_bin\\Release-Win32\\loader.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Drixed_E_2147692488_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Drixed.E"
        threat_id = "2147692488"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Drixed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 4d 0c 30 08 8b c7 42 e8 ?? ?? ?? ?? 3b d0 7c e7}  //weight: 1, accuracy: Low
        $x_1_2 = {bf ef be ad de eb 1e 6a 04 8d 43 0c 68}  //weight: 1, accuracy: High
        $x_1_3 = {80 30 aa 42 3b d6 7c ef}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Drixed_F_2147692661_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Drixed.F"
        threat_id = "2147692661"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Drixed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ef be ad de eb 01 00 02 01 01 bf be}  //weight: 1, accuracy: Low
        $x_1_2 = {80 30 aa 42 3b d6 7c ef}  //weight: 1, accuracy: High
        $x_1_3 = {c7 40 08 f7 28 9e 50}  //weight: 1, accuracy: High
        $x_1_4 = {8d 78 10 8b 45 ?? 8b 55 ?? 33 07 33 57 04 83 65 0c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

