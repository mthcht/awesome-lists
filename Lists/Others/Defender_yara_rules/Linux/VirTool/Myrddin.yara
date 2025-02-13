rule VirTool_Linux_Myrddin_DS_2147793919_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Linux/Myrddin.DS!MTB"
        threat_id = "2147793919"
        type = "VirTool"
        platform = "Linux: Linux platform"
        family = "Myrddin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MerlinClient" ascii //weight: 1
        $x_1_2 = "SendMerlinMessage" ascii //weight: 1
        $x_1_3 = {6e 65 74 2e 54 43 50 43 6f 6e 6e [0-60] 6e 65 74 2e 55 44 50 41 64 64 72 [0-60] 6e 65 74 2e 55 44 50 43 6f 6e [0-60] 6e 65 74 2e 6e 73 73 43 6f 6e 66 [0-60] 6e 65 74 2e 72 61 77 43 6f 6e 6e}  //weight: 1, accuracy: Low
        $x_1_4 = "mythic.Task" ascii //weight: 1
        $x_1_5 = "KeyLogWriter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

