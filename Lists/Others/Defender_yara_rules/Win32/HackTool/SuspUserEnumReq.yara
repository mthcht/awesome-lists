rule HackTool_Win32_SuspUserEnumReq_2147948803_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/SuspUserEnumReq"
        threat_id = "2147948803"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspUserEnumReq"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "curl " wide //weight: 5
        $x_5_2 = "--oauth2-bearer " wide //weight: 5
        $x_5_3 = "graph.windows.net/" wide //weight: 5
        $x_1_4 = "userprincipalname" wide //weight: 1
        $x_1_5 = "netid" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

