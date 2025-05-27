rule Trojan_Win64_AgentWinDis_PA_2147942249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AgentWinDis.PA!MTB"
        threat_id = "2147942249"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AgentWinDis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /f /im MsMpEng.exe >nul 2>&1" ascii //weight: 1
        $x_2_2 = "vssadmin delete shadows /all /quiet >nul 2>&1" ascii //weight: 2
        $x_1_3 = "powershell -command \"Set-MpPreference -DisableRealtimeMonitoring $true" ascii //weight: 1
        $x_1_4 = "shutdown /s /f /t 0 /c \"Windows Update" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

