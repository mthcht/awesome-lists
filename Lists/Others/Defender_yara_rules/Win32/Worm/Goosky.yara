rule Worm_Win32_Goosky_A_2147684258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Goosky.A"
        threat_id = "2147684258"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Goosky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {32 4d ff fe 45 ff 88 0e 46 38 45 ff 72 e6}  //weight: 10, accuracy: High
        $x_5_2 = "Software\\Skype\\Phone\\UI" wide //weight: 5
        $x_5_3 = "(facepalm)" wide //weight: 5
        $x_1_4 = "larawang ito" wide //weight: 1
        $x_1_5 = "this photo" wide //weight: 1
        $x_1_6 = "detta foto" wide //weight: 1
        $x_1_7 = "Allah Allah" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

