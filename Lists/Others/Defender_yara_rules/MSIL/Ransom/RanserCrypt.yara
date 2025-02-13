rule Ransom_MSIL_RanserCrypt_PA_2147781481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/RanserCrypt.PA!MTB"
        threat_id = "2147781481"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RanserCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "UnlockYourFiles.Login" ascii //weight: 1
        $x_1_2 = "81c5fc0d-3ddd-44b6-810e-7c1ce636d3de" wide //weight: 1
        $x_1_3 = {61 03 61 0a 7e ?? ?? ?? ?? 0d 09 06 93 0b 7e ?? ?? ?? ?? 07 9a 25 13 ?? 2c 03}  //weight: 1, accuracy: Low
        $x_1_4 = {11 05 11 08 09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 17 11 08 58 13 08 00 11 08 08 fe 04 2d da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

