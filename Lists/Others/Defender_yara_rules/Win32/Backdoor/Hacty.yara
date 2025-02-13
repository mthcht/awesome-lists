rule Backdoor_Win32_Hacty_D_2147650553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hacty.D"
        threat_id = "2147650553"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hacty"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 5c 24 10 38 1c 16 74 ?? 8b fe 83 c9 ff 33 c0 42 f2 ae f7 d1 49 3b d1 72}  //weight: 1, accuracy: Low
        $x_1_2 = "mhackeryythac1977" ascii //weight: 1
        $x_1_3 = "The backdoor is running" ascii //weight: 1
        $x_1_4 = "InjectThread:\"%s\" error code:%d" ascii //weight: 1
        $x_1_5 = "Modth.Flag=%x,Modth.ModifyModth=%x,Modth.StartModth=%x" ascii //weight: 1
        $x_1_6 = "Begin to start hacker's door" ascii //weight: 1
        $x_1_7 = {8a 01 0f b6 71 01 88 45 fb 0f b6 c0 c1 e0 04 33 c6 0f b6 71 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

