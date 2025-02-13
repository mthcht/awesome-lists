rule Trojan_Win64_SysChange_SA_2147890103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SysChange.SA!MTB"
        threat_id = "2147890103"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SysChange"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HideIcons" wide //weight: 1
        $x_1_2 = "winlock\\lck\\lck\\x64\\Release\\lck.pdb" ascii //weight: 1
        $x_1_3 = "DisableTaskMgr" wide //weight: 1
        $x_1_4 = "DisableChangePassword" wide //weight: 1
        $x_1_5 = "DisableLockWorkstation" wide //weight: 1
        $x_1_6 = "CurrentVersion\\Policies\\Explorer Hidden" wide //weight: 1
        $x_1_7 = "Explorer\\HideDesktopIcons\\NewStartPane" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

