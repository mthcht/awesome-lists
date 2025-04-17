rule Trojan_Win32_SuspDefenderExclusions_SH_2147939262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspDefenderExclusions.SH"
        threat_id = "2147939262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspDefenderExclusions"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "& c:\\windows\\system32\\windowspowershell\\" ascii //weight: 2
        $x_2_2 = "powershell.exe -exec bypass -command" ascii //weight: 2
        $x_2_3 = "add-mppreference" ascii //weight: 2
        $x_1_4 = "-exclusionpath" ascii //weight: 1
        $x_1_5 = "-exclusionextension" ascii //weight: 1
        $x_1_6 = "-exclusionprocess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

