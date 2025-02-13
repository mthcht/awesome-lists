rule VirTool_MSIL_Cajan_A_2147760885_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Cajan.A!MTB"
        threat_id = "2147760885"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cajan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "winpeas" ascii //weight: 2
        $x_1_2 = "S3cur3Th1sSh1t/SharpByeBear" ascii //weight: 1
        $x_1_3 = "CVE_2019_1405" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_Cajan_B_2147763878_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Cajan.B!MTB"
        threat_id = "2147763878"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cajan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "winpeas" ascii //weight: 1
        $x_1_2 = "S3cur3Th1sSh1t/SharpByeBear" ascii //weight: 1
        $x_1_3 = "CVE_2019_1405" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

