rule Trojan_Win32_Wewer_A_2147627885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wewer.A"
        threat_id = "2147627885"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wewer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://wermeer.cn/wermeer/report.php?title=" ascii //weight: 1
        $x_1_2 = "@taskkill /f /im svchost.exe" ascii //weight: 1
        $x_1_3 = "\\vip.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

