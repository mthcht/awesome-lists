rule Trojan_Win32_ProcKiller_B_2147758153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ProcKiller.B!MTB"
        threat_id = "2147758153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ProcKiller"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iDetect_VIP.bat" ascii //weight: 1
        $x_1_2 = "b2eincfilecount" wide //weight: 1
        $x_1_3 = "rundll32 USER32.DLL,SwapMouseButton" ascii //weight: 1
        $x_1_4 = "Policies\\System /v DisableTaskMgr /t REG_SZ /d 1 /f" ascii //weight: 1
        $x_1_5 = "net stop WinDefend" ascii //weight: 1
        $x_1_6 = "Leak by $hatra" ascii //weight: 1
        $x_1_7 = "taskkill /f /t /im FirewallControlPanel.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_ProcKiller_C_2147762698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ProcKiller.C!MTB"
        threat_id = "2147762698"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ProcKiller"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "cmd /c taskkill.exe /f /im svchost.exe" wide //weight: 10
        $x_1_2 = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide //weight: 1
        $x_1_3 = "regwrite" wide //weight: 1
        $x_1_4 = "1.vbp" wide //weight: 1
        $x_1_5 = "vb6chs.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

