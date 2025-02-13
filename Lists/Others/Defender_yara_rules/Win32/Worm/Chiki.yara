rule Worm_Win32_Chiki_A_2147626282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Chiki.A"
        threat_id = "2147626282"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Chiki"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "I just want to say I love Milko and I need a drink" ascii //weight: 3
        $x_1_2 = "_Fichiers.exe" ascii //weight: 1
        $x_1_3 = "_Saves.exe" ascii //weight: 1
        $x_1_4 = "\\chiCkie.exe" ascii //weight: 1
        $x_1_5 = {57 3a 00 00 58 3a 00 00 59 3a 00 00 5a 3a 00 00}  //weight: 1, accuracy: High
        $x_4_6 = {be 18 00 00 00 bb ?? ?? ?? ?? 8b 03 50 e8 ?? ?? ?? ?? 83 f8 02 0f 85 36 01 00 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

