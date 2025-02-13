rule Worm_Win32_Texbot_A_2147671269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Texbot.A"
        threat_id = "2147671269"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Texbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 73 00 74 00 61 00 72 00 74 00 6d 00 73 00 67 00 73 00 70 00 72 00 65 00 61 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 2a 00 66 00 61 00 63 00 65 00 62 00 6f 00 6f 00 6b 00 2e 00 63 00 6f 00 6d 00 2a 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 6d 6f 64 52 75 6e 41 70 70 4d 65 6d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

