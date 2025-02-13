rule HackTool_Linux_Mweb_A_2147824650_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Mweb.A!xp"
        threat_id = "2147824650"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Mweb"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mweb scan" ascii //weight: 1
        $x_1_2 = "mscanning from %s (pid: %d)" ascii //weight: 1
        $x_1_3 = "UnlG - backd00r" ascii //weight: 1
        $x_1_4 = "GET /cgi-bin/man.sh HTTP/1.0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

