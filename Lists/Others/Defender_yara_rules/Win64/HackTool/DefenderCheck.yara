rule HackTool_Win64_DefenderCheck_DMX_2147948873_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/DefenderCheck.DMX!MTB"
        threat_id = "2147948873"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "DefenderCheck"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DefenderCheck" ascii //weight: 1
        $x_1_2 = "LS0tIEZJUkVGT1ggUEFTU1dPUkRTIC0tLQ==" ascii //weight: 1
        $x_1_3 = "LS0tIENIUk9NRSBQQVNTV09SRFMgLS0t" ascii //weight: 1
        $x_1_4 = "aHR0cHM6Ly9hcGkudGVsZWdyYW0ub3JnL2JvdA==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

