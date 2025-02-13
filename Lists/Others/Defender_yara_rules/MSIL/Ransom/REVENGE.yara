rule Ransom_MSIL_REVENGE_DB_2147784679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/REVENGE.DB!MTB"
        threat_id = "2147784679"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "REVENGE"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 08 5d 0b 03 07 6f ?? ?? ?? 0a 1f 41 59 13 04 06 09 02 09 91 11 04 58 20 00 01 00 00 5d d2 9c 07 17 58 0b 00 09 17 58 0d 09 02 8e 69 fe 04 13 05 11 05 2d ca}  //weight: 10, accuracy: Low
        $x_1_2 = "GeneratePassword" ascii //weight: 1
        $x_1_3 = "encryptDirectory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

