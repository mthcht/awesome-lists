rule Worm_Win32_Duptwux_A_2147646117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Duptwux.A"
        threat_id = "2147646117"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Duptwux"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 02 88 04 0f 47 83 c2 04 39 f2 7c ee 4b 85 db 7d e3}  //weight: 1, accuracy: High
        $x_1_2 = {3c 41 74 04 3c 61 75 0b 8d ?? ?? ?? ff ff e9 ?? ?? ?? ?? 8d ?? ?? ?? ff ff e9 ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 83 f8 02}  //weight: 1, accuracy: Low
        $x_1_3 = {80 3c 03 4d 75 ?? 80 7c 03 05 73 75 ?? 80 7c 03 08 74 75 ?? 80 7c 03 0c 6e 75 ?? 80 7c 03 0f 77}  //weight: 1, accuracy: Low
        $x_1_4 = {80 3c 3e 4d 0f 85 ?? ?? ?? ?? 80 7c 3e 05 73 0f 85 ?? ?? ?? ?? 80 7c 3e 08 74 0f 85 ?? ?? ?? ?? 80 7c 3e 0c 6e 0f 85 ?? ?? ?? ?? 80 7c 3e 0f 77}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

