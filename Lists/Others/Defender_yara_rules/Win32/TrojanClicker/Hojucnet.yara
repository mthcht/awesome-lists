rule TrojanClicker_Win32_Hojucnet_A_2147628149_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Hojucnet.A"
        threat_id = "2147628149"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Hojucnet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "|kpfw32.exe|rfwmain.exe|RSTray.exe|" wide //weight: 1
        $x_1_2 = "SELECT * FROM Win32_NetworkAdapterConfiguration" wide //weight: 1
        $x_1_3 = "/cpmlist4.txt" wide //weight: 1
        $x_1_4 = "taskkill /f /im" wide //weight: 1
        $x_1_5 = ".cn/tongji/post.asp" wide //weight: 1
        $x_1_6 = "rass32.exe" wide //weight: 1
        $x_1_7 = "ping 127.1" wide //weight: 1
        $x_1_8 = "tmrClick" ascii //weight: 1
        $x_1_9 = "DownLoadConfig" ascii //weight: 1
        $x_1_10 = "IfDelMe" ascii //weight: 1
        $x_1_11 = "Pass_Decode" ascii //weight: 1
        $x_1_12 = "TongJi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

