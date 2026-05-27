rule Ransom_MSIL_Dominiko_AMTB_2147970311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Dominiko!AMTB"
        threat_id = "2147970311"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dominiko"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\obj\\Debug\\Dominiko.pdb" ascii //weight: 2
        $x_1_2 = "Dominiko was here" ascii //weight: 1
        $x_2_3 = "FILE_HAHA_DOMINIKO" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

