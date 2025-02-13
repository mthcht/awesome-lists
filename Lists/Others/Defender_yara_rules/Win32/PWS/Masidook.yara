rule PWS_Win32_Masidook_A_2147641210_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Masidook.A"
        threat_id = "2147641210"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Masidook"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s_history_%d:%d" ascii //weight: 1
        $x_1_2 = "NL$%d(%d):" ascii //weight: 1
        $x_1_3 = "SECURITY\\Policy\\Secrets\\NL$KM\\CurrVal" ascii //weight: 1
        $x_1_4 = "msdk.dat" ascii //weight: 1
        $x_2_5 = "%s:%d:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x:%02x" wide //weight: 2
        $x_2_6 = {f3 a5 8b c8 83 e1 03 f3 a4 e8 ?? ?? ff ff 85 c0 74 7f b9 06 00 00 00 33 c0 8d 7c 24 50 8d 54 24 50 f3 ab 8d 4c 24 2c c7 44 24 50 18 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

