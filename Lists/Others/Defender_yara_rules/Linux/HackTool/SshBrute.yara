rule HackTool_Linux_SshBrute_A_2147781811_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SshBrute.A!MTB"
        threat_id = "2147781811"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SshBrute"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Brute ssh attack finished!" ascii //weight: 1
        $x_1_2 = "SSH attack on port" ascii //weight: 1
        $x_1_3 = "pass.lst" ascii //weight: 1
        $x_1_4 = "Check ip: %s with user %s and pass %s on port:" ascii //weight: 1
        $x_1_5 = "ips.lst" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

