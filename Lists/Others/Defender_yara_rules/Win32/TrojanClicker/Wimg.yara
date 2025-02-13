rule TrojanClicker_Win32_Wimg_A_2147689608_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Wimg.A"
        threat_id = "2147689608"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Wimg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "cn|dygo%nsnwzziyd|xny%nsnwfjs" wide //weight: 4
        $x_3_2 = "wbns{gdyn%nsnw" wide //weight: 3
        $x_3_3 = "|iexplore.exe|theworld.exe|qqbrowser.exe|maxthon.exe|gree" wide //weight: 3
        $x_5_4 = ".html' target='_self'><div id='ggg'></div></a> " wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

