rule Backdoor_Win32_Fibot_A_2147711522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Fibot.A"
        threat_id = "2147711522"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Fibot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/logger/post.php?bot_id=%s&cmd=%s" ascii //weight: 1
        $x_1_2 = "/logger/command.php?bot_id=%s&os=%s&hostname=%s&time=%s" ascii //weight: 1
        $x_1_3 = "/logger/upload.php?bot_id=%s&cmd=%s&path=%s" ascii //weight: 1
        $x_1_4 = "42.112.29.21" ascii //weight: 1
        $x_1_5 = "C:\\Users\\%s\\AppData\\Local\\Temp\\Fixed.exe" ascii //weight: 1
        $x_1_6 = "C:\\Documents and Settings\\%s\\Application Data\\Fixed.exe" ascii //weight: 1
        $x_1_7 = "cliresult.txt" ascii //weight: 1
        $x_1_8 = "Bot install success" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

