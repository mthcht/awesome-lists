rule Ransom_MSIL_Deniz_K_2147750882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Deniz.K!MSR"
        threat_id = "2147750882"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Deniz"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Deniz_Kizi.NET" wide //weight: 2
        $x_2_2 = "ReadME" wide //weight: 2
        $x_1_3 = {65 00 76 00 62 00 [0-5] 74 00 6d 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

