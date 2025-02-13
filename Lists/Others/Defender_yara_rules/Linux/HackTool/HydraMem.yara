rule HackTool_Linux_HydraMem_A_2147805415_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/HydraMem.A!!HydraMem.A"
        threat_id = "2147805415"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "HydraMem"
        severity = "High"
        info = "HydraMem: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "HELO hydra" ascii //weight: 2
        $x_2_2 = "EHLO hydra" ascii //weight: 2
        $x_2_3 = "Mozilla/5.0 (Hydra Proxy)" ascii //weight: 2
        $x_2_4 = "./hydra.restore was written" ascii //weight: 2
        $x_2_5 = "hydra -L userlist.txt" ascii //weight: 2
        $x_2_6 = "[STATUS] attack finished for %s" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

