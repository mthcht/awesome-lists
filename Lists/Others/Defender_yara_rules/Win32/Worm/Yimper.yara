rule Worm_Win32_Yimper_2147646415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Yimper"
        threat_id = "2147646415"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Yimper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ymsgr:SendIM?" ascii //weight: 1
        $x_1_2 = "\\autorun.inf" ascii //weight: 1
        $x_1_3 = "USER=%s PASS=%s" ascii //weight: 1
        $x_1_4 = {41 75 74 6f 52 75 6e [0-2] 5d [0-2] 0d 0a 4f 50 45 4e 3d}  //weight: 1, accuracy: Low
        $x_2_5 = {6a 01 68 58 04 00 00 68 00 01 00 00 6a 02 ?? ff d0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

