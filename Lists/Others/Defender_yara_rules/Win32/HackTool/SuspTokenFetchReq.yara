rule HackTool_Win32_SuspTokenFetchReq_2147948804_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/SuspTokenFetchReq"
        threat_id = "2147948804"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspTokenFetchReq"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "roadtx " wide //weight: 5
        $x_5_2 = "appauth " wide //weight: 5
        $x_5_3 = "aadgraph" wide //weight: 5
        $x_1_4 = "--cert-pfx" wide //weight: 1
        $x_1_5 = "--pfx-pass" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

