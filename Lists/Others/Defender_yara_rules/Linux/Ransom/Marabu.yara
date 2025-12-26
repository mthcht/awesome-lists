rule Ransom_Linux_Marabu_A_2147960119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Marabu.A!MTB"
        threat_id = "2147960119"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Marabu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "create_ransom_note" ascii //weight: 1
        $x_1_2 = "encrypt_file" ascii //weight: 1
        $x_1_3 = ".marabu" ascii //weight: 1
        $x_1_4 = "READ_THIS_NOTE.txt" ascii //weight: 1
        $x_1_5 = "secure_remove_file" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

