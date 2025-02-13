rule Backdoor_Linux_Vganuw_B_2147916427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Vganuw.B"
        threat_id = "2147916427"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Vganuw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.HandleRunProcess" ascii //weight: 1
        $x_1_2 = "main.HandleDeleteFile" ascii //weight: 1
        $x_1_3 = "main.HandleUpload" ascii //weight: 1
        $x_1_4 = "main.HandleFileManager" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

