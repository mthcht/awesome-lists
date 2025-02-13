rule HackTool_Linux_Dcomer_A_2147824985_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Dcomer.A!xp"
        threat_id = "2147824985"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Dcomer"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Usage: %s <a-block> <port> [b-block] [c-block]" ascii //weight: 1
        $x_1_2 = "bde Exp $" ascii //weight: 1
        $x_1_3 = "obrien Exp $" ascii //weight: 1
        $x_1_4 = "Attempting RPC/DCOM on" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

