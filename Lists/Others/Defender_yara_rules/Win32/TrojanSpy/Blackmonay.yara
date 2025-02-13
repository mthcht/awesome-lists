rule TrojanSpy_Win32_Blackmonay_A_2147650981_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Blackmonay.A"
        threat_id = "2147650981"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Blackmonay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BlackMoon RunTime" ascii //weight: 2
        $x_2_2 = "page_alert(){return;}" ascii //weight: 2
        $x_2_3 = "<input type=hidden id=\"dddbh\" name=\"dddbh\" value=" ascii //weight: 2
        $x_2_4 = "&Bank=ICBC&Money=88" ascii //weight: 2
        $x_2_5 = "Api/163/Post.Php?UserName=" ascii //weight: 2
        $x_2_6 = "cut_tips=1&rdo=rdo&gameid=&_server_id" ascii //weight: 2
        $x_1_7 = "AMD ISBETTER" ascii //weight: 1
        $x_1_8 = "e161255a-37c3-11d2-bcaa-00c04fd929db" ascii //weight: 1
        $x_1_9 = "%s\\%s\\%s.lnk" ascii //weight: 1
        $x_1_10 = "1FBA04EE-3024-11D2-8F1F-0000F87ABD16" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((6 of ($x_2_*))) or
            (all of ($x*))
        )
}

