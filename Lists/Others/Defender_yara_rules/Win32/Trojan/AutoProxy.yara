rule Trojan_Win32_AutoProxy_GJL_2147848101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoProxy.GJL!MTB"
        threat_id = "2147848101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoProxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/baijiahei/sample_mailslotok" ascii //weight: 1
        $x_1_2 = "106.55.149.249" ascii //weight: 1
        $x_1_3 = "/baijiahei/dll.dll" ascii //weight: 1
        $x_1_4 = "/baijiahei/exe.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

