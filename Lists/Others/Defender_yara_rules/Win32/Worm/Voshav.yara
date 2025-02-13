rule Worm_Win32_Voshav_A_2147689332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Voshav.A"
        threat_id = "2147689332"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Voshav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 70 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 ?? ?? ?? ?? ?? ?? 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 00 65 00 78 00 65 00 ?? ?? ?? ?? ?? ?? ?? ?? 5c 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00}  //weight: 1, accuracy: Low
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run-" wide //weight: 1
        $x_1_4 = "\\sYs__Tem.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

