rule Trojan_Win32_Vmprotbad_AMQ_2147787870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vmprotbad.AMQ!MTB"
        threat_id = "2147787870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vmprotbad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\Windows\\explorer.exe" ascii //weight: 3
        $x_3_2 = "SeDebugPrivilege" ascii //weight: 3
        $x_3_3 = "xz.dt399.cn" ascii //weight: 3
        $x_3_4 = "URLDownloadToFileA" ascii //weight: 3
        $x_3_5 = "WTSSendMessageW" ascii //weight: 3
        $x_3_6 = "WTSQueryUserToken" ascii //weight: 3
        $x_3_7 = "GetProcessAffinityMask" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

