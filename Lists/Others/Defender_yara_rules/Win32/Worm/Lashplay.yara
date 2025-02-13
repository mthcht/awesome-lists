rule Worm_Win32_Lashplay_A_2147604934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Lashplay.gen!A"
        threat_id = "2147604934"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Lashplay"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\explorer\\Browser Helper Objects\\" ascii //weight: 1
        $x_1_2 = "http://ling.pc37.com/flashplay.dll" ascii //weight: 1
        $x_1_3 = "http://www.96163.cn/down/" ascii //weight: 1
        $x_1_4 = "\\flashplay.dll" ascii //weight: 1
        $x_1_5 = "baidu" ascii //weight: 1
        $x_1_6 = "explorerbar" ascii //weight: 1
        $x_1_7 = "\\ms_start.exe" ascii //weight: 1
        $x_1_8 = ":\\autorun.inf" ascii //weight: 1
        $x_1_9 = ".exe autorun" ascii //weight: 1
        $x_1_10 = "Iyaodiange" ascii //weight: 1
        $x_1_11 = "shj_play.htm" ascii //weight: 1
        $x_1_12 = "zhenguoyin" ascii //weight: 1
        $x_1_13 = {5c 24 24 66 6c 61 73 [0-1] 68 70 24 24 2e 62 61 74}  //weight: 1, accuracy: Low
        $x_1_14 = "\\win_*" ascii //weight: 1
        $x_1_15 = ":37/pc37/" ascii //weight: 1
        $x_1_16 = "rename flashplay.dll flashplay.dll_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

