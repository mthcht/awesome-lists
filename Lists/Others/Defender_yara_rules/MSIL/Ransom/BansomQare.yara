rule Ransom_MSIL_BansomQare_A_2147731340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/BansomQare.A"
        threat_id = "2147731340"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BansomQare"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".trobibtc218" wide //weight: 1
        $x_1_2 = "Send $100 worth of bitcoin to this address:" wide //weight: 1
        $x_1_3 = "a680e5e6-a07c-4f4b-8600-b8015f6f2888" ascii //weight: 1
        $x_1_4 = "Ooops , Your file have been encrypted!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

