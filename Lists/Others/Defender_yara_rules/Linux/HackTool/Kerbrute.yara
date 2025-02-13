rule HackTool_Linux_Kerbrute_A_2147844225_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Kerbrute.A!MTB"
        threat_id = "2147844225"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Kerbrute"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Kerbrute" ascii //weight: 1
        $x_1_2 = "bruteuser" ascii //weight: 1
        $x_1_3 = "github.com/ropnop/kerbrute/cmd" ascii //weight: 1
        $x_1_4 = "*cobra.Command" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

