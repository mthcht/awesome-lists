rule Trojan_Win64_Killfiles_PAGZ_2147958672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Killfiles.PAGZ!MTB"
        threat_id = "2147958672"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Killfiles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DisableAntiSpyware" ascii //weight: 2
        $x_2_2 = "vssadmin.exe delete shadows /all /quiet" ascii //weight: 2
        $x_1_3 = "Set-MpPreference -EnableControlledFolderAccess Disabled" ascii //weight: 1
        $x_1_4 = "bcdedit /set {current} recoveryenabled off" ascii //weight: 1
        $x_1_5 = "bcdedit /set {current} advancedoptions off" ascii //weight: 1
        $x_2_6 = "Add-MpPreference -ExclusionPath @($env:UserProfile, $env:ProgramData, $env:ProgramFiles, $env:ProgramFiles (x86)) -ExclusionExtension '.exe' -ExclusionProcess" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

