rule Ransom_MSIL_SolixCrypt_PA_2147846708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/SolixCrypt.PA!MTB"
        threat_id = "2147846708"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SolixCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "your_image_name.jpg" wide //weight: 1
        $x_1_2 = ".Solix" wide //weight: 1
        $x_1_3 = "Your files have been encrypted!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

