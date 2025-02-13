rule Ransom_MSIL_Vouscrypt_A_2147723941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Vouscrypt.A"
        threat_id = "2147723941"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vouscrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/YourRansom/main.go" ascii //weight: 1
        $x_1_2 = "/YourRansom/funcs.go" ascii //weight: 1
        $x_1_3 = {3b 61 08 0f 86 12 03 00 00 83 ec 54 8b 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 50 01 8b 5c 24 5c 39 d3 0f 8c e9 02 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "YR0x02.key" ascii //weight: 1
        $x_1_5 = "\"Just smile :)" ascii //weight: 1
        $x_1_6 = "\"EncSuffix\":" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

