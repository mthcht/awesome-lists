rule Backdoor_Win32_Slackbot_F_2147706451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Slackbot.F"
        threat_id = "2147706451"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Slackbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "NICK %s" ascii //weight: 1
        $x_1_2 = "changed%s%s%sTo%s%s" ascii //weight: 1
        $x_1_3 = "copyme" ascii //weight: 1
        $x_1_4 = "?Killed=" ascii //weight: 1
        $x_1_5 = "!SendkeyLogToServer" ascii //weight: 1
        $x_1_6 = {2e 00 65 00 78 00 65 00 74 00 6d 00 70 00 [0-4] 2e 00 76 00 62 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

