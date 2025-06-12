rule Ransom_Linux_Metamorphic_A_2147943544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Metamorphic.A!MTB"
        threat_id = "2147943544"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Metamorphic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "metamorphic_malware_generator" ascii //weight: 1
        $x_1_2 = "malware_2_metamorphic" ascii //weight: 1
        $x_1_3 = "malware_2_processed_source" ascii //weight: 1
        $x_1_4 = "Randomware by [afjoseph]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

