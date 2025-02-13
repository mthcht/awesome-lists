rule Ransom_MSIL_GlobeImposter_E_2147920464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/GlobeImposter.E!MTB"
        threat_id = "2147920464"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GlobeImposter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LockBit Black" ascii //weight: 1
        $x_1_2 = "All your important files are stolen and encrypted!" ascii //weight: 1
        $x_1_3 = "README.txt file" ascii //weight: 1
        $x_1_4 = "and follow the instruction!" ascii //weight: 1
        $x_1_5 = "{0}\\how_to_back_files.html" ascii //weight: 1
        $x_1_6 = "{0}\\WallPaper.bmp" ascii //weight: 1
        $x_1_7 = "YOUR COMPANY NETWORK HAS BEEN PENETRATED" ascii //weight: 1
        $x_1_8 = "Your files are safe! Only modified." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

