rule Ransom_Linux_Mario_A_2147901031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Mario.A!MTB"
        threat_id = "2147901031"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Mario"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".mario" ascii //weight: 1
        $x_1_2 = "RansomHouse" ascii //weight: 1
        $x_1_3 = "/path/to/be/encrypted" ascii //weight: 1
        $x_1_4 = "How To Restore Your Files.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

