rule Trojan_Win32_gen8_RDA_2147887426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/gen8.RDA!MTB"
        threat_id = "2147887426"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "gen8"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "pfjmwbvyp" ascii //weight: 2
        $x_2_2 = "RVcnIfycf.exe" ascii //weight: 2
        $x_1_3 = "SHELLEXECUTE ( @WORKINGDIR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

