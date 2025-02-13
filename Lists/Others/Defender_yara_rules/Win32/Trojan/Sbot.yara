rule Trojan_Win32_Sbot_VW_2147896105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sbot.VW!MTB"
        threat_id = "2147896105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.baidu.com" ascii //weight: 1
        $x_1_2 = "nwp100@163.com" ascii //weight: 1
        $x_1_3 = "Data.mdb" ascii //weight: 1
        $x_1_4 = "GetProcAddress" ascii //weight: 1
        $x_1_5 = "LoadResource" ascii //weight: 1
        $x_1_6 = "GetTickCount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

