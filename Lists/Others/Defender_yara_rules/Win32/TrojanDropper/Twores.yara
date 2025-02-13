rule TrojanDropper_Win32_Twores_2147605381_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Twores"
        threat_id = "2147605381"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Twores"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "EnumResourceNamesA" ascii //weight: 1
        $x_1_2 = "LoadResource" ascii //weight: 1
        $x_1_3 = "SizeofResource" ascii //weight: 1
        $x_4_4 = {00 4f 50 45 4e 00}  //weight: 4, accuracy: High
        $x_4_5 = {6a 00 68 80 00 00 00 6a 02 6a 00 6a 02 68 00 00 00 40}  //weight: 4, accuracy: High
        $x_10_6 = {8a 44 10 ff 8a 54 1d ff 32 c2 88 07 47 43 8b c5 e8 ?? ?? ?? ?? 3b d8 7e 05 bb 01 00 00 00 ff 44 24 ?? 4e 75}  //weight: 10, accuracy: Low
        $x_10_7 = {83 e8 01 72 0a 74 1b 48 74 2b 48 74 3b eb 4a 68 04 01 00 00 8d 85 ?? ?? ff ff 50 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_4_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Twores_L_2147632033_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Twores.L"
        threat_id = "2147632033"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Twores"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 30 8b 54 24 ?? 34 ?? 42 57 88 06 6a 00 89 54 24 ?? 46 ff d5 39 44 24 00 72 e0 8b 74 24}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 68 80 00 00 00 6a 02 6a 00 6a 02 68 00 00 00 40}  //weight: 1, accuracy: High
        $x_1_3 = "LoadResource" ascii //weight: 1
        $x_1_4 = "SizeofResource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

