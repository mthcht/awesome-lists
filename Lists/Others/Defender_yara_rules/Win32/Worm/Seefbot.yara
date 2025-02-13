rule Worm_Win32_Seefbot_A_2147596949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Seefbot.gen!A"
        threat_id = "2147596949"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Seefbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tSkMainForm.UnicodeClass" ascii //weight: 1
        $x_1_2 = "PuTTY" ascii //weight: 1
        $x_1_3 = "TFrmMain" ascii //weight: 1
        $x_1_4 = "YahooBuddyMain" ascii //weight: 1
        $x_1_5 = "MSBLWindowClass" ascii //weight: 1
        $x_1_6 = "_Oscar_StatusNotify" ascii //weight: 1
        $x_1_7 = "__oxFrame.class__" ascii //weight: 1
        $x_1_8 = "PRIVMSG %s :WGET  %s\\%s  %s [%s]" ascii //weight: 1
        $x_1_9 = "main.remove" ascii //weight: 1
        $x_1_10 = "%s\\temp%i%i%i%i.bat" ascii //weight: 1
        $x_1_11 = {6a 09 5b 99 8b cb f7 f9 52 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

