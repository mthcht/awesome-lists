rule Worm_Win32_Adept_A_2147621456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Adept.A"
        threat_id = "2147621456"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Adept"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 04 2a 8a 14 31 32 d0 88 14 31 41 3b cf 7c eb}  //weight: 2, accuracy: High
        $x_2_2 = {68 90 00 00 00 52 56 ff 15}  //weight: 2, accuracy: High
        $x_1_3 = "ru/folder.ico" ascii //weight: 1
        $x_1_4 = "=system.vbs" ascii //weight: 1
        $x_1_5 = "ShellBotR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

