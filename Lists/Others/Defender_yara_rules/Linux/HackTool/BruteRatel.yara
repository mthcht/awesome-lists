rule HackTool_Linux_BruteRatel_A_2147890017_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/BruteRatel.A!MTB"
        threat_id = "2147890017"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "BruteRatel"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.MitreStruct" ascii //weight: 1
        $x_1_2 = "url.Userinfo" ascii //weight: 1
        $x_1_3 = "victimsize" ascii //weight: 1
        $x_1_4 = "ForceAttemptHTTP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

