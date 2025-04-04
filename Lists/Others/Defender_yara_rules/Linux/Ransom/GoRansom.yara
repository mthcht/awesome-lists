rule Ransom_Linux_GoRansom_A_2147847903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/GoRansom.A!MTB"
        threat_id = "2147847903"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "GoRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.ransomware" ascii //weight: 1
        $x_1_2 = "Encrypt" ascii //weight: 1
        $x_1_3 = ".decrypt" ascii //weight: 1
        $x_1_4 = "main.start.func1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

