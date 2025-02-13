rule DDoS_Win32_Fareit_A_2147652749_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Fareit.gen!A"
        threat_id = "2147652749"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {75 0e b8 3d 00 00 00 c7 45 fc 01 00 00 00 eb 1b b8 26 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {8b 40 0c 0b c0 75 07 b8 ff ff ff ff eb 04 8b 00 8b 00}  //weight: 2, accuracy: High
        $x_2_3 = {ff 85 0c f9 ff ff 83 bd 0c f9 ff ff 0a 73 05 e9 4a ff ff ff}  //weight: 2, accuracy: High
        $x_1_4 = "PNYDOS00" ascii //weight: 1
        $x_1_5 = "CRYPTED0" ascii //weight: 1
        $x_1_6 = "BINSTR00" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

