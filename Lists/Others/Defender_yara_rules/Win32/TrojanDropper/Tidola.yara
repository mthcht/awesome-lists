rule TrojanDropper_Win32_Tidola_A_2147620360_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Tidola.A"
        threat_id = "2147620360"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Tidola"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {85 db 74 0b 83 c6 14 81 fe 59 07 00 00 72 8d}  //weight: 3, accuracy: High
        $x_3_2 = {83 f8 11 75 3d a1 ?? ?? ?? ?? 0f b6 40 02 83 f8 01 74 0e a1 ?? ?? ?? ?? 0f b6 40 02 83 f8 03}  //weight: 3, accuracy: Low
        $x_1_3 = {00 c9 cf b5 c4 b6 af 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 c8 eb c3 dc b1 a3 bf a8 00}  //weight: 1, accuracy: High
        $x_1_5 = {61 63 74 3d 26 64 31 30 3d 25 73 26 64 38 30 3d 25 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Tidola_B_2147620361_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Tidola.B"
        threat_id = "2147620361"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Tidola"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 63 74 3d 26 64 31 30 3d 25 73 26 64 38 30 3d 25 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {63 7e 24 7e 6d 64 20 7e 24 7e 2f 63 20 7e 24 7e 64 65 7e 24 7e 6c 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 64 72 69 7e 24 7e 76 65 72 73 5c 65 7e 24 7e 74 63 5c 68 6f 73 7e 24 7e 74 73 00}  //weight: 1, accuracy: High
        $x_1_4 = "%s~$~%s~$~*~$~.dll" ascii //weight: 1
        $x_1_5 = "expl~$~orer.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

