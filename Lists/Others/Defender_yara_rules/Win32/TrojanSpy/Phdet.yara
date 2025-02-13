rule TrojanSpy_Win32_Phdet_B_2147689532_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Phdet.B"
        threat_id = "2147689532"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Phdet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 9b 14 af ab 6a 01 e8 ?? ?? ?? ?? 89 45 fc 8b 45 08 50 ff 55 fc}  //weight: 3, accuracy: Low
        $x_1_2 = {77 70 73 63 61 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {66 61 69 6c 65 64 2e 20 4e 6f 74 20 61 20 53 79 73 74 65 6d 2e 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

