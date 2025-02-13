rule HackTool_MacOS_Rubilyn_B_2147748670_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Rubilyn.B!MTB"
        threat_id = "2147748670"
        type = "HackTool"
        platform = "MacOS: "
        family = "Rubilyn"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "debug.rubilyn." ascii //weight: 1
        $x_1_2 = "enter icmp path for backdoor:" ascii //weight: 1
        $x_1_3 = "HARDCORE EST. 1983" ascii //weight: 1
        $x_1_4 = "enter process id to give root:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

