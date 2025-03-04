rule Trojan_Win32_AntiVm_EM_2147850223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AntiVm.EM!MTB"
        threat_id = "2147850223"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AntiVm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VMwareService.exe" wide //weight: 1
        $x_1_2 = "VMwareTray.exe" wide //weight: 1
        $x_1_3 = "BitDefender" wide //weight: 1
        $x_1_4 = "mssecess.exe" wide //weight: 1
        $x_1_5 = "QuickHeal" wide //weight: 1
        $x_1_6 = "cangku\\WinOsClientProject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

