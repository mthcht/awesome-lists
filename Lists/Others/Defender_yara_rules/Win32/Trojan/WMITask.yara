rule Trojan_Win32_WMITask_HE_2147948960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WMITask.HE!MTB"
        threat_id = "2147948960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WMITask"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft.Win32.TaskScheduler.dll" ascii //weight: 1
        $x_1_2 = "Newtonsoft.Json.dll" ascii //weight: 1
        $x_30_3 = "\\msedge_proxy.exe --app=https://www.tradingview." ascii //weight: 30
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_30_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

