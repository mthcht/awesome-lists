rule HackTool_Win32_MicroKMS_2147734039_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/MicroKMS"
        threat_id = "2147734039"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "MicroKMS"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "microkms.txt" ascii //weight: 1
        $x_1_2 = "www.yishimei.cn" ascii //weight: 1
        $x_1_3 = "MicroKMS" ascii //weight: 1
        $x_1_4 = "DisableRealtimeMonitoring" ascii //weight: 1
        $x_1_5 = "dl.lmrjxz.com" ascii //weight: 1
        $x_1_6 = "microkms.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

