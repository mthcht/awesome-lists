rule Ransom_MSIL_SupsoCrypt_PA_2147795387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/SupsoCrypt.PA!MTB"
        threat_id = "2147795387"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SupsoCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 16 0b 2b 1d 02 07 6f ?? 00 00 0a 1f 7b 61 d1 0c 06 08 8c ?? 00 00 01 28 ?? 00 00 0a 0a 07 17 58 0b 07 02 6f ?? 00 00 0a 32 da}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

