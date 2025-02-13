rule Ransom_MSIL_Crawl_A_2147722654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Crawl.A!bit"
        threat_id = "2147722654"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crawl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your system files has been encrypted" wide //weight: 1
        $x_1_2 = "your_encryption_public_key.rkf" wide //weight: 1
        $x_1_3 = "http://sigmalab.lv/other/crypt/" wide //weight: 1
        $x_1_4 = "SOFTWARE\\crawl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

