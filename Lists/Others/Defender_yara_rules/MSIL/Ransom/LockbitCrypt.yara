rule Ransom_MSIL_LockbitCrypt_SVA_2147840421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LockbitCrypt.SVA!MTB"
        threat_id = "2147840421"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LockbitCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 04 11 07 11 08 20 00 01 00 00 5d d2 9c 11 08 20 00 01 00 00 5b 13 08 11 07 17 58 13 07 11 07 1a 32 dd}  //weight: 1, accuracy: High
        $x_1_2 = {72 1a 16 00 70 28 17 00 00 0a 0a 72 30 16 00 70 0b 07 72 6e 16 00 70 28 17 00 00 0a 0b 07 72 23 17 00 70 28 17 00 00 0a 0b 07 72 c6 17 00 70 28 17 00 00 0a 0b 07 72 1a 18 00 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

