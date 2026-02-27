rule HackTool_Win64_KillEDR_GH_2147963844_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/KillEDR.GH!MTB"
        threat_id = "2147963844"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "KillEDR"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Firmware\\OemHwUpd.sys" ascii //weight: 1
        $x_1_2 = "sentinelservice.exe" wide //weight: 1
        $x_1_3 = "mssense.exe" wide //weight: 1
        $x_1_4 = "sophossps.exe" wide //weight: 1
        $x_1_5 = "avastsvc.exe" wide //weight: 1
        $x_1_6 = "elastic-endpoint.exe" wide //weight: 1
        $x_1_7 = "\\\\.\\OemHwUpd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

