rule Worm_Win32_Gorabot_A_2147649499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gorabot.A"
        threat_id = "2147649499"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gorabot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s %s \"\" \"lol\" :%s" ascii //weight: 1
        $x_1_2 = "%.wipmania.com" ascii //weight: 1
        $x_1_3 = "%s\\%s.exe" ascii //weight: 1
        $x_1_4 = {25 73 20 25 73 20 3a 25 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {50 52 49 56 4d 53 47 00}  //weight: 1, accuracy: High
        $x_10_6 = {44 6f 77 6e 6c 6f 61 64 20 63 75 72 72 65 6e 74 6c 79 20 61 63 74 69 76 65 21 00}  //weight: 10, accuracy: High
        $x_10_7 = {55 70 64 61 74 65 20 63 75 72 72 65 6e 74 6c 79 20 61 63 74 69 76 65 21 00}  //weight: 10, accuracy: High
        $x_10_8 = {42 6f 74 6b 69 6c 6c 65 72 20 61 63 74 69 76 65 21 00}  //weight: 10, accuracy: High
        $x_10_9 = "Terminated: \"DDoSer\" %s:%d" ascii //weight: 10
        $x_10_10 = "Terminated: \"Metus\" %s:%d" ascii //weight: 10
        $x_10_11 = "Terminated: \"IRC Bot\" %s:%d" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

