rule TrojanSpy_MSIL_Kabolog_A_2147682128_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Kabolog.A"
        threat_id = "2147682128"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kabolog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {08 06 16 20 b3 ea 65 15 20 b3 da 65 15 59 6f a4 00 00 0a 13 08}  //weight: 5, accuracy: High
        $x_5_2 = "@kola-boka" wide //weight: 5
        $x_1_3 = "[Guillemets]" wide //weight: 1
        $x_1_4 = "set_HKB" ascii //weight: 1
        $x_1_5 = "capsshift" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

