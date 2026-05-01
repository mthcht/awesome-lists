rule HackTool_Win64_Zusy_AHA_2147968185_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Zusy.AHA!MTB"
        threat_id = "2147968185"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "Usage: /browsersinfo" ascii //weight: 30
        $x_20_2 = "Usage: /infects" ascii //weight: 20
        $x_10_3 = "Usage: /passfucker <user> <new_password>" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

