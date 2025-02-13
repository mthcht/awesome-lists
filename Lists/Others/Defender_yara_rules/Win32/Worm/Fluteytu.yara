rule Worm_Win32_Fluteytu_A_2147646070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Fluteytu.A"
        threat_id = "2147646070"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Fluteytu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 ff 42 c7 45 f8 ?? ?? ?? ?? 8d 45 f4 8a 55 ff e8 ?? ?? ?? ?? 8d 45 f4 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 f4 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 f8 02 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {80 fb 41 72 2a 80 fb 5b 77 25 6a 14 e8}  //weight: 1, accuracy: High
        $x_1_3 = {80 38 2e 0f 84 ?? ?? ff ff ba 07 00 00 00 8b 45 fc e8 ?? ?? ?? ?? 8d 45 fc ba}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

