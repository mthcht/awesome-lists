rule Backdoor_Win32_BazarLoader_2147775170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/BazarLoader!MTB"
        threat_id = "2147775170"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" ascii //weight: 1
        $x_1_2 = "NoRun" ascii //weight: 1
        $x_1_3 = "NoDrives" ascii //weight: 1
        $x_1_4 = "RestrictRun" ascii //weight: 1
        $x_1_5 = "NoNetConnectDisconnect" ascii //weight: 1
        $x_1_6 = "NoRecentDocsHistory" ascii //weight: 1
        $x_1_7 = "NoClose" ascii //weight: 1
        $x_1_8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Network" ascii //weight: 1
        $x_1_9 = "NoEntireNetwork" ascii //weight: 1
        $x_1_10 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Comdlg32" ascii //weight: 1
        $x_1_11 = "4096" wide //weight: 1
        $x_1_12 = "NTDLL.dll" wide //weight: 1
        $x_1_13 = "Fuck Def" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

