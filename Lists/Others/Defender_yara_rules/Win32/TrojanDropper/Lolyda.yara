rule TrojanDropper_Win32_Lolyda_B_2147624561_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Lolyda.B"
        threat_id = "2147624561"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 1c 30 80 f3 19 88 1c 30 40 3b c1 72 ee}  //weight: 1, accuracy: High
        $x_1_2 = {74 0e 8a 14 01 80 f2 86 88 14 01 40 3b c7 72 f2}  //weight: 1, accuracy: High
        $x_1_3 = "$$$$______$$$$" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Lolyda_D_2147629675_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Lolyda.D"
        threat_id = "2147629675"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "FONtS\\ComRes.dll" ascii //weight: 1
        $x_1_2 = "FontS\\gth%02x*.ttf" ascii //weight: 1
        $x_1_3 = {2d 20 05 00 00 8d 8d ?? ?? ?? ?? 50 68 20 05 00 00 8d 95 ?? ?? ?? ?? 51 52 e8 [0-15] 90 [0-15] 8d 85 ?? ?? ?? ?? 68 20 05 00 00 8d 8d ?? ?? ?? ?? 50 51 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Lolyda_F_2147630503_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Lolyda.F"
        threat_id = "2147630503"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 b8 d4 07 66 ab 33 c0 66 b8 08 00 66 ab 33 c0 66 b8 08 00}  //weight: 1, accuracy: High
        $x_1_2 = {83 7d 0c 00 75 1f 8b 7d fc 8b 55 08 8b df 2b d3 83 ea 05 89 55 f8 b0 e9 aa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

