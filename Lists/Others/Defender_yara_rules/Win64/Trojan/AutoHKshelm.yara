rule Trojan_Win64_AutoHKshelm_RB_2147844085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AutoHKshelm.RB!MTB"
        threat_id = "2147844085"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AutoHKshelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cmd.exe /c POWeRSHeLL.eXe -NOP -WIND HIDDeN -eXeC BYPASS -NONI < Key\\PerfLogs\\logo.jpg  ,,hide" ascii //weight: 1
        $x_1_2 = "Cmd.exe /c POWeRSHeLL.eXe -NOP -WIND HIDDeN -eXeC BYPASS -NONI < Key\\PerfLogs\\EnterpriseAppMgmtSvc.jpg" ascii //weight: 1
        $x_1_3 = "Cmd.exe /c POWeRSHeLL.eXe -NOP -WIND HIDDeN -eXeC BYPASS -NONI < Key\\PerfLogs\\AppXDeploymentServer.jpg" ascii //weight: 1
        $x_1_4 = "Key\\en-US\\Fonts\\1.exe" ascii //weight: 1
        $x_1_5 = "%AppData%\\PerfLogs\\Key.vbs" ascii //weight: 1
        $x_1_6 = "FileExist(\"C:\\ProgramData\\Avira\\\")" ascii //weight: 1
        $x_1_7 = "FileRemoveDir, %AppData%\\PerfLogs\\PerfLogs, 1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

