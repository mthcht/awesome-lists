rule Ransom_Win32_Purubutu_A_2147688855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Purubutu.A"
        threat_id = "2147688855"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Purubutu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "; rv:x.xx) Gecko/20030504 Mozilla Firebird/0.6" wide //weight: 1
        $x_1_2 = "ollydbg.exe" wide //weight: 1
        $x_1_3 = "\\SOFTWARE\\Classes\\Folder\\shell\\sandbox" wide //weight: 1
        $x_1_4 = "hiew32.exe" wide //weight: 1
        $x_1_5 = "Delete Shadows /All /Quiet" wide //weight: 1
        $x_1_6 = {4c 00 6f 00 63 00 6b 00 65 00 64 00 3a 00 [0-80] 50 00 43 00 3a 00 [0-48] 49 00 44 00 3a 00 [0-48] 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3a 00}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 55 fc 0f b7 54 5a fe 33 d7 66 89 54 58 fe 43 4e 75 e5 8b 45 f8 8b 55 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Purubutu_B_2147688856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Purubutu.B"
        threat_id = "2147688856"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Purubutu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 54 5a fe 33 d7 66 89 54 58 fe 43 4e 75 e5}  //weight: 1, accuracy: High
        $x_1_2 = "Delete Shadows /All /Quiet" wide //weight: 1
        $x_1_3 = "native.CBC" wide //weight: 1
        $x_10_4 = {36 01 24 01 29 01 20 01 36 01 05 01 37 01 2c 01 35 01 2a 01 29 01 24 01 6b 01 2b 01 20 01 31 01}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

