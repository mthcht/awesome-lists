rule Worm_Win32_Coinficon_A_2147712479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Coinficon.A"
        threat_id = "2147712479"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Coinficon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "\\NsMiner\\IMG001.exe" ascii //weight: 4
        $x_4_2 = "testswork.ru/info.zip" ascii //weight: 4
        $x_1_3 = "\\info.zip" ascii //weight: 1
        $x_2_4 = {c7 00 61 61 61 61 c7 40 04 61 61 61 61 c7 40 08 61 61 61 61}  //weight: 2, accuracy: High
        $x_2_5 = {c7 04 24 10 27 00 00 c7 85 ?? ?? ff ff ff ff ff ff e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

