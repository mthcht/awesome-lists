rule VirTool_Win32_Dominicus_A_2147760765_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Dominicus.A"
        threat_id = "2147760765"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Dominicus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DeimosC2/DeimosC2/agents" ascii //weight: 1
        $x_1_2 = "DeimosC2/DeimosC2/lib" ascii //weight: 1
        $x_1_3 = "http.http2ClientConn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

