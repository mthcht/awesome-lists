rule HackTool_MacOS_Earthworm_A_2147746215_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Earthworm.A!MTB"
        threat_id = "2147746215"
        type = "HackTool"
        platform = "MacOS: "
        family = "Earthworm"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.rootkiter.com/EarthWorm/" ascii //weight: 1
        $x_1_2 = "./xxx -c [rhost] -p [rport]" ascii //weight: 1
        $x_1_3 = "./agent_exe -l 8888" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule HackTool_MacOS_Earthworm_B_2147749832_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Earthworm.B!MTB"
        threat_id = "2147749832"
        type = "HackTool"
        platform = "MacOS: "
        family = "Earthworm"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rootkiter.com/EarthWrom/" ascii //weight: 1
        $x_1_2 = "./xxx -h -s ssocksd" ascii //weight: 1
        $x_1_3 = "./ew -s lcx_listen -l 1080 -e 8888" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

