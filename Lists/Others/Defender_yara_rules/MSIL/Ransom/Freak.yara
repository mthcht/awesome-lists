rule Ransom_MSIL_Freak_MK_2147792894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Freak.MK!MTB"
        threat_id = "2147792894"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Freak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "your system is infected with freak.ransom" ascii //weight: 1
        $x_1_2 = "freak ransom" ascii //weight: 1
        $x_1_3 = "your files are encrypted with public key" ascii //weight: 1
        $x_1_4 = "you can get your files back by paying" ascii //weight: 1
        $x_1_5 = "is my computer damaged?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

