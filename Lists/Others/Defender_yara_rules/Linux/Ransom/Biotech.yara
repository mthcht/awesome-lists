rule Ransom_Linux_Biotech_A_2147893459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Biotech.A!MTB"
        threat_id = "2147893459"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Biotech"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "black_letter.txt" ascii //weight: 1
        $x_1_2 = "%s.biotech" ascii //weight: 1
        $x_1_3 = "encrypt_file" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

