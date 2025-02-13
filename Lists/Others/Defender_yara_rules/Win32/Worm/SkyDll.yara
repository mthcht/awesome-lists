rule Worm_Win32_SkyDll_A_2147692419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SkyDll.A"
        threat_id = "2147692419"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SkyDll"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "lol!!! {fullname} video: http://" ascii //weight: 3
        $x_2_2 = "/sfcfg.txt" ascii //weight: 2
        $x_1_3 = "skype_restart_mins" ascii //weight: 1
        $x_1_4 = "old_friend_hours" ascii //weight: 1
        $x_1_5 = "del_msgs_limit" ascii //weight: 1
        $x_1_6 = "send_strategy" ascii //weight: 1
        $x_1_7 = "max_loc_msgs" ascii //weight: 1
        $x_1_8 = "someskype.com" ascii //weight: 1
        $x_1_9 = "someskype.net" ascii //weight: 1
        $x_1_10 = "letskype.net" ascii //weight: 1
        $x_1_11 = "ironskype.net" ascii //weight: 1
        $x_1_12 = "deepskype.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

