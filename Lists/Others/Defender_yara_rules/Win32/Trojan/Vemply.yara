rule Trojan_Win32_Vemply_DA_2147899387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vemply.DA!MTB"
        threat_id = "2147899387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vemply"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/config/gjc.txt" ascii //weight: 1
        $x_1_2 = "mobile.yangkeduo.com" ascii //weight: 1
        $x_1_3 = "item.taobao.com" ascii //weight: 1
        $x_1_4 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_5 = "ShellExecuteA" ascii //weight: 1
        $x_1_6 = "V5m.com" ascii //weight: 1
        $x_1_7 = "WinHttpCrackUrl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

