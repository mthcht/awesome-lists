rule Backdoor_Win32_Yewbmoat_2147606610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Yewbmoat"
        threat_id = "2147606610"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Yewbmoat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {ff ff ff ff 0d 00 00 00 66 6d 69 64 65 70 6c 6f 79 2e 65 78 65 00 00 00 ff ff ff ff}  //weight: 3, accuracy: High
        $x_3_2 = {ff ff ff ff 0c 00 00 00 69 61 73 72 65 63 73 74 2e 65 78 65 00 00 00 00 ff ff}  //weight: 3, accuracy: High
        $x_3_3 = {77 65 62 79 61 74 6f 6d 00 00 00 00 55 8b ec 33 c0 55 68}  //weight: 3, accuracy: High
        $x_2_4 = {8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41 41 eb 03 83 c1 05 01 c1}  //weight: 2, accuracy: High
        $x_1_5 = "kill_begin" ascii //weight: 1
        $x_1_6 = "kill_end" ascii //weight: 1
        $x_1_7 = "delete_begin" ascii //weight: 1
        $x_1_8 = "delete_end" ascii //weight: 1
        $x_1_9 = "&status=1&version=" ascii //weight: 1
        $x_1_10 = "usrsvpia.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

