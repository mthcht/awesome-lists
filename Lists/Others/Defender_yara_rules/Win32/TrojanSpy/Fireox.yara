rule TrojanSpy_Win32_Fireox_B_2147607523_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Fireox.B"
        threat_id = "2147607523"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Fireox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 5c 73 69 67 6e 6f 6e 73 32 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_2 = "ffpscache.tmp" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Mozilla\\Mozilla Firefox" ascii //weight: 1
        $x_1_4 = "FtpPutFileA" ascii //weight: 1
        $x_1_5 = {33 c0 55 68 74 55 40 00 64 ff 30 64 89 20 6a 00 6a 00 6a 00 6a 01 68 84 55 40 00 e8 b7 f7 ff ff 8b d8 6a 00 68 00 00 00 08 6a 01 8b 45 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

