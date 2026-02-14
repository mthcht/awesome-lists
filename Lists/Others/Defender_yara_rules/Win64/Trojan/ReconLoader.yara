rule Trojan_Win64_ReconLoader_CM_2147963066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ReconLoader.CM!MTB"
        threat_id = "2147963066"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ReconLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "is_vm=%d&av_software=%s" ascii //weight: 2
        $x_2_2 = "/c powershell.exe -WindowStyle Hidden -Command \"Add-MpPreference -ExclusionPath '%s%s'\"" ascii //weight: 2
        $x_2_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_2_4 = "exfil_data=%s" ascii //weight: 2
        $x_2_5 = "VMware" ascii //weight: 2
        $x_2_6 = "VirtualBox" ascii //weight: 2
        $x_2_7 = "securitycenter2 path antivirusproduct" ascii //weight: 2
        $x_2_8 = "payload\":" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

