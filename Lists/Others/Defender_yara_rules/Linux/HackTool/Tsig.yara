rule HackTool_Linux_Tsig_A_2147830763_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Tsig.A!xp"
        threat_id = "2147830763"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Tsig"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "usage: %s address [-s][-e]" ascii //weight: 1
        $x_1_2 = "-e send exploit packet" ascii //weight: 1
        $x_1_3 = "-s send infoleak packet" ascii //weight: 1
        $x_1_4 = "successfully exploited" ascii //weight: 1
        $x_1_5 = "chmod +x d0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

