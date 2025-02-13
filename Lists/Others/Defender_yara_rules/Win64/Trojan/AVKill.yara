rule Trojan_Win64_AVKill_A_2147906571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AVKill.A!MTB"
        threat_id = "2147906571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AVKill"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Powershell -Command \"$wshell=New-Object -ComObject wscript.shell; $wshell.SendKeys('" ascii //weight: 2
        $x_2_2 = "Powershell -Command \"Get-MpPreference" ascii //weight: 2
        $x_2_3 = "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows Defender Security Center\\Notifications\" /v \"DisableNotifications\" /t reg_DWORD /d \"1\" /f" ascii //weight: 2
        $x_2_4 = "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Systray\" /v \"HideSystray\" /t reg_DWORD /d \"1\" /f" ascii //weight: 2
        $x_2_5 = "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan\" /v \"DisableScanningMappedNetworkDrivesForFullScan\" /t reg_DWORD /d \"1\" /f" ascii //weight: 2
        $x_2_6 = "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan\" /v \"DisableScanningNetworkFiles\" /t reg_DWORD /d \"1\" /f" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

