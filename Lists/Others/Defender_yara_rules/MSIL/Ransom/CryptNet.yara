rule Ransom_MSIL_CryptNet_MA_2147847811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptNet.MA!MTB"
        threat_id = "2147847811"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptNet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 0e 18 5b 02 8e 69 18 5b 11 09 5a 59 13 10}  //weight: 2, accuracy: High
        $x_2_2 = "9ddf9d3e-f6a7-4d59-99a5-f4504fef52b8" ascii //weight: 2
        $x_2_3 = "o2b7eNVjYJ4gqsEoouj.SQOwhjVfrxWErP6jVXa" ascii //weight: 2
        $x_2_4 = {57 b5 02 3c 09 0f 00 00 00 00 00 00 00 00 00 00 02 00 00 00 8d 00 00 00 24}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

