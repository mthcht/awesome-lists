rule VirTool_MSIL_Sharpup_A_2147944840_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Sharpup.A"
        threat_id = "2147944840"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sharpup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HijackablePaths" ascii //weight: 1
        $x_1_2 = "PrivescChecks" ascii //weight: 1
        $x_1_3 = "vulnerableChecks" ascii //weight: 1
        $x_1_4 = "TokenGroupsAndPrivileges" ascii //weight: 1
        $x_1_5 = "ModifiableServiceBinaries" ascii //weight: 1
        $x_1_6 = "GetRegValues" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

