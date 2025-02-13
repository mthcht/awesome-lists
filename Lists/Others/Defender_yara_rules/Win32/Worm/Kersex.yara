rule Worm_Win32_Kersex_A_2147583069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Kersex.A"
        threat_id = "2147583069"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Kersex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 2a 2e 2a 00}  //weight: 1, accuracy: High
        $x_2_2 = "Caster v1." ascii //weight: 2
        $x_2_3 = "Easy ScreenSaver Studio v3" ascii //weight: 2
        $x_2_4 = "promt Professional English-" ascii //weight: 2
        $x_2_5 = {2e 63 7a 69 70 00}  //weight: 2, accuracy: High
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_2_7 = "C:\\WINDOWS\\shared\\" ascii //weight: 2
        $x_2_8 = "deflate 1.2.3 Copyright 1995" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((6 of ($x_2_*))) or
            (all of ($x*))
        )
}

