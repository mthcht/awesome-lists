rule Ransom_Linux_Soleenya_A3_2147908288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Soleenya.A3"
        threat_id = "2147908288"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Soleenya"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "How To Restore Your Files.txt" ascii //weight: 2
        $x_2_2 = "SOLEENYA RANSOMWARE" ascii //weight: 2
        $x_2_3 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii //weight: 2
        $x_2_4 = ".slnya" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

