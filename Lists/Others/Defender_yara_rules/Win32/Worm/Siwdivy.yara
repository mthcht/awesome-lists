rule Worm_Win32_Siwdivy_A_2147707624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Siwdivy.A"
        threat_id = "2147707624"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Siwdivy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 06 41 c6 46 01 3a c6 46 02 5c c6 46 03 00 56 e8 ?? ?? ?? ?? 83 f8 02 75 06}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 06 20 2e 6c 6e 6b 00 68}  //weight: 1, accuracy: High
        $x_1_3 = {eb 06 2c 70 30 31 20 00 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

