rule Trojan_Win32_SuspExc_Z_2147978275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspExc.Z!MTB"
        threat_id = "2147978275"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspExc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Add-MpPreference" wide //weight: 1
        $x_1_2 = "-ExclusionPath" wide //weight: 1
        $x_1_3 = "$env:UserProfile" wide //weight: 1
        $x_1_4 = "force" wide //weight: 1
        $x_1_5 = "powershell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

