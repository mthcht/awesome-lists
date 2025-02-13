rule HackTool_Win32_QQFarm_A_2147642279_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/QQFarm.A"
        threat_id = "2147642279"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "QQFarm"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "F600363078DE49c5B10AF62C7A13B37E" ascii //weight: 2
        $x_2_2 = ".59tou.com" ascii //weight: 2
        $x_1_3 = {20 37 30 38 32 38 30 00}  //weight: 1, accuracy: High
        $x_1_4 = {61 77 61 72 64 6e 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_5 = "&benew0908=1" ascii //weight: 1
        $x_1_6 = "&frienduin=" ascii //weight: 1
        $x_1_7 = "/rosary09" ascii //weight: 1
        $x_1_8 = "anquan.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

