rule VirTool_Win64_Golsass_A_2147927351_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Golsass.A"
        threat_id = "2147927351"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Golsass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.installService" ascii //weight: 1
        $x_1_2 = "smb/dcerpc.BindReq" ascii //weight: 1
        $x_1_3 = "main.cleanup" ascii //weight: 1
        $x_1_4 = "icmplocalhostlsass.dmplsass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

