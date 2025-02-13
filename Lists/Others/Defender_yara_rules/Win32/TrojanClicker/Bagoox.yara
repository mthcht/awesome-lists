rule TrojanClicker_Win32_Bagoox_A_2147706484_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Bagoox.A"
        threat_id = "2147706484"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Bagoox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "server1.baigou51.com:9988/lianjs/lianjs.txt" ascii //weight: 1
        $x_1_2 = "http://server1.baigou51.com:886/user/" ascii //weight: 1
        $x_1_3 = "systemq\\svchost.exe" ascii //weight: 1
        $x_1_4 = "http://hometj.webok.net:1234/tongji.asp?wwwip=" ascii //weight: 1
        $x_1_5 = "_guanggao_pub=" ascii //weight: 1
        $x_1_6 = "document.body.insertBefore(e, document.body.children.item(0))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

