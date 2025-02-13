rule VirTool_Win32_HtWorkz_A_2147808497_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/HtWorkz.A!MTB"
        threat_id = "2147808497"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "HtWorkz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uploadheadscreenshot" ascii //weight: 1
        $x_1_2 = "useragent" ascii //weight: 1
        $x_1_3 = "ipcheckurl" ascii //weight: 1
        $x_1_4 = "heartbeat" ascii //weight: 1
        $x_1_5 = "port" ascii //weight: 1
        $x_1_6 = "uploadheadfile" ascii //weight: 1
        $x_1_7 = "xorkey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

