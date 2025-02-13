rule TrojanSpy_Win32_AgentKlog_SW_2147804295_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/AgentKlog.SW!MTB"
        threat_id = "2147804295"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentKlog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "namebro" wide //weight: 1
        $x_1_2 = "[ ALTDOWN ]" wide //weight: 1
        $x_1_3 = "[Escape]" wide //weight: 1
        $x_1_4 = "WScript.Shell" wide //weight: 1
        $x_1_5 = "taskkill /im" wide //weight: 1
        $x_1_6 = "cmd.exe /c timeout.exe /T 11 & Del" wide //weight: 1
        $x_1_7 = "WantToCle Log" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_AgentKlog_SN_2147804296_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/AgentKlog.SN!MTB"
        threat_id = "2147804296"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentKlog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "warka\\kul\\201-solitaire\\Solitaire.vbp" wide //weight: 1
        $x_1_2 = "http://hem1.passagen.se/fylke/" wide //weight: 1
        $x_1_3 = "anders.fransson@home.se" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

