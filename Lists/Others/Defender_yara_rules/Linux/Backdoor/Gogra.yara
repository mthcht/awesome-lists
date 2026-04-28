rule Backdoor_Linux_Gogra_A_2147967887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gogra.A"
        threat_id = "2147967887"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gogra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.filedroping" ascii //weight: 1
        $x_1_2 = "main.creatingDesktopfile" ascii //weight: 1
        $x_1_3 = "main.CreateServiceFile" ascii //weight: 1
        $x_1_4 = "main.DropEmbededFile" ascii //weight: 1
        $x_1_5 = "embed.FS.ReadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

