rule Trojan_Win64_AntiVm_NE_2147915268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AntiVm.NE!MTB"
        threat_id = "2147915268"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AntiVm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "cositas.pdb" ascii //weight: 4
        $x_1_2 = "taskkill/IM.exe" ascii //weight: 1
        $x_1_3 = "/C-ExclusionPathAdd-MpPreference" ascii //weight: 1
        $x_1_4 = "powershell.execmd.exeProcessTracker.exeWindowsDefender.exestart" ascii //weight: 1
        $x_1_5 = "regaddHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System/vConsentPromptBehaviorAdmin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

