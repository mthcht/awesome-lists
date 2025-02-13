rule PWS_Win32_Waimup_A_2147613010_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Waimup.A"
        threat_id = "2147613010"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Waimup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 2c da 92 00 8b 00 83 c0 20 8b 00 05 04 05 00 00 8b 00 b9 10 27 00 00 33 d2 f7 f1}  //weight: 1, accuracy: High
        $x_1_2 = {6a 02 6a 00 68 ef fe ff ff 53 e8 ?? ?? ?? ?? 8d 45 ?? e8 ?? ?? ?? ?? 6a 00 68 fc cd 40 00 68 11 01 00 00 a1 ?? ?? ?? ?? 50 53 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

