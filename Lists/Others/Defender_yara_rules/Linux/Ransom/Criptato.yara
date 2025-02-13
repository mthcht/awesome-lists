rule Ransom_Linux_Criptato_A_2147901499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Criptato.A!MTB"
        threat_id = "2147901499"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Criptato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = ".fuck" ascii //weight: 5
        $x_5_2 = ".crypt" ascii //weight: 5
        $x_5_3 = {00 2e 2e 00 56 49 53 49 54 4f 20 25 73 20 43 48 45 20 43 4f 4e 54 49 45 4e 45 20 25 73 0a 00 72 62 00 77 62 00}  //weight: 5, accuracy: High
        $x_1_4 = "criptato" ascii //weight: 1
        $x_1_5 = "VisitDecrypt" ascii //weight: 1
        $x_1_6 = "VisitCrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

