rule HackTool_Win32_DefenderDel_SA_2147834558_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DefenderDel.SA"
        threat_id = "2147834558"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DefenderDel"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "remove windows defender" ascii //weight: 10
        $x_10_2 = "are you sure you want to delete windows defender" ascii //weight: 10
        $x_10_3 = "defender remover will" ascii //weight: 10
        $x_10_4 = "p2cserv" ascii //weight: 10
        $x_1_5 = "disablerealtimemonitoring" ascii //weight: 1
        $x_1_6 = "disableantivirus" ascii //weight: 1
        $x_1_7 = "disableantispyware" ascii //weight: 1
        $x_1_8 = "program files (x86)\\windows defender advanced threat protection" ascii //weight: 1
        $x_1_9 = "program files\\windows defender advanced threat protection" ascii //weight: 1
        $x_1_10 = "programdata\\microsoft\\windows defender advanced threat protection" ascii //weight: 1
        $x_1_11 = "programdata\\microsoft\\storage health" ascii //weight: 1
        $x_1_12 = "wdboot.sys" ascii //weight: 1
        $x_1_13 = "wddevflt.sys" ascii //weight: 1
        $x_1_14 = "wdfilter.sys" ascii //weight: 1
        $x_1_15 = "wdnisdrv.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_DefenderDel_SB_2147834559_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DefenderDel.SB"
        threat_id = "2147834559"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DefenderDel"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "p2cserv" ascii //weight: 10
        $x_1_2 = "disablerealtimemonitoring" ascii //weight: 1
        $x_1_3 = "disableantivirus" ascii //weight: 1
        $x_1_4 = "disableantispyware" ascii //weight: 1
        $x_1_5 = "program files (x86)\\windows defender advanced threat protection" ascii //weight: 1
        $x_1_6 = "program files\\windows defender advanced threat protection" ascii //weight: 1
        $x_1_7 = "programdata\\microsoft\\windows defender advanced threat protection" ascii //weight: 1
        $x_1_8 = "programdata\\microsoft\\storage health" ascii //weight: 1
        $x_1_9 = "wdboot.sys" ascii //weight: 1
        $x_1_10 = "wddevflt.sys" ascii //weight: 1
        $x_1_11 = "wdfilter.sys" ascii //weight: 1
        $x_1_12 = "wdnisdrv.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

