rule TrojanClicker_Win32_Jofita_A_2147611497_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Jofita.A"
        threat_id = "2147611497"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Jofita"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 af eb 2b 66 3d 22 00 74 2f 66 3d 27 00 74 29 41 66 3d 3a 00 75 10 ff 05}  //weight: 1, accuracy: High
        $x_1_2 = {3b f7 6a 02 5b 0f 84 e8 00 00 00 83 c6 0c eb 02 03 f3 0f b7 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

