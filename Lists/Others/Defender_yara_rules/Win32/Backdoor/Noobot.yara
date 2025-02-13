rule Backdoor_Win32_Noobot_A_2147652762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Noobot.A"
        threat_id = "2147652762"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Noobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 4c 00 00 50 4b 00 00 50 46 00 00 47 46 00 00 43 4d 00 00 53 43 00 00 45 43 4d 00 45 53 43 00 53 4c 00 00 45 58 00 00 50 52 00 00 52 55 00 00 55 44}  //weight: 1, accuracy: High
        $x_1_2 = {54 41 52 00 53 49 50 00 4d 52 4b 00 50 58 59 00 42 50 53 00 54 4c 53 00 4e 41 4d 45 00 00 00 00 41 44 44 52 00 00 00 00 4d 41 52 4b}  //weight: 1, accuracy: High
        $x_1_3 = "Kugoosoft" wide //weight: 1
        $x_1_4 = "MoonClient" ascii //weight: 1
        $x_1_5 = {73 79 75 6e 00 00 00 00 2f 69 6d 61 67 65 73 2f 69 63 6f 6e 73 2f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

