rule Ransom_MSIL_CryCrypt_PA_2147806104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryCrypt.PA!MTB"
        threat_id = "2147806104"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "712065b9-17a2-401a-81bb-2489055e183b" wide //weight: 1
        $x_1_2 = "$8d733b60-8631-4c4a-bdeb-8cf0438492f1" ascii //weight: 1
        $x_1_3 = {06 02 07 6f [0-4] 7e [0-4] 07 7e [0-4] 8e 69 5d 91 61 28 [0-4] 6f [0-4] 26 07 17 58 0b 07 02 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

