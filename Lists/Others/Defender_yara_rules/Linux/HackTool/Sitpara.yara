rule HackTool_Linux_Sitpara_A_2147822865_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Sitpara.A!xp"
        threat_id = "2147822865"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Sitpara"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Syntax: %s [-dflsSTbvDFPR] [-p percent] [-m MAC] INTERFACE" ascii //weight: 1
        $x_1_2 = "killed flooding" ascii //weight: 1
        $x_1_3 = "dflm:svDFp:PRS:T:b" ascii //weight: 1
        $x_1_4 = "constantly flood" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

