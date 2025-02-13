rule TrojanSpy_Win32_Vinelai_A_2147649666_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Vinelai.A"
        threat_id = "2147649666"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Vinelai"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/enviamail.php" ascii //weight: 1
        $x_1_2 = {44 33 33 37 41 39 32 46 39 43 33 32 41 30 33 42 46 36 30 32 30 34 35 41 41 38 37 37 38 43 00}  //weight: 1, accuracy: High
        $x_1_3 = {be 01 00 00 00 8b 45 e8 0f b6 44 30 ff 33 d8 8d 45 cc 50 89 5d d0 c6 45 d4 00 8d 55 d0 33 c9 b8 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

