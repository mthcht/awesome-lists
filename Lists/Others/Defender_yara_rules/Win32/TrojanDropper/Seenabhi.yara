rule TrojanDropper_Win32_Seenabhi_A_2147688338_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Seenabhi.A"
        threat_id = "2147688338"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Seenabhi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c6 45 fc 4d c6 45 fd 5a 88 5d fe c6 45 f4 d8 88 5d f5 88 5d f6}  //weight: 2, accuracy: High
        $x_2_2 = {c6 45 f4 4a 51 50 c6 45 f5 75 c6 45 f6 73 c6 45 f7 74 c6 45 f8 54 c6 45 f9 65 c6 45 fa 6d c6 45 fb 70 c6 45 fc 46 c6 45 fd 75 c6 45 fe 6e}  //weight: 2, accuracy: High
        $x_1_3 = {c6 45 b0 77 3b c3 c6 45 b1 69 c6 45 b2 6e c6 45 b3 6c c6 45 b4 6f c6 45 b5 67 c6 45 b6 2e c6 45 b7 6c c6 45 b8 6e c6 45 b9 6b}  //weight: 1, accuracy: High
        $x_1_4 = {c6 45 c8 70 c6 45 c9 73 c6 45 ca 6c c6 45 cb 6f c6 45 cc 67 c6 45 cd 2e c6 45 ce 74 c6 45 cf 78 c6 45 d0 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

