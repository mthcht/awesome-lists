rule TrojanClicker_Win32_Sadbick_A_2147626277_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Sadbick.A"
        threat_id = "2147626277"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Sadbick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/PushMission2Client03.asp" wide //weight: 1
        $x_1_2 = "&Publicer=" wide //weight: 1
        $x_1_3 = "MAC=" wide //weight: 1
        $x_1_4 = "User-Agent: ClickAdsByIE" wide //weight: 1
        $x_1_5 = "Accept-Language: zh-cn,zh;q=0.5" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

