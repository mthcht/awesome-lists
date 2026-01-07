rule Trojan_MSIL_Acrstealer_PGAS_2147960679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Acrstealer.PGAS!MTB"
        threat_id = "2147960679"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Acrstealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {47 00 5a 00 56 00 58 00 64 00 54 00 4b 00 7a 00 7a 00 74 00 69 00 6b 00 69 00 4a 00 4c 00 [0-2] 4d 00 78 00 68 00 57 00 7a 00 79 00 6f 00 59 00 4f 00 70 00 67 00 6e 00 62 00 63 00 69 00 [0-2] 69 00 50 00 7a 00 68 00 48 00 73 00 46 00 57 00 70 00 6c 00 58 00 63 00 48 00 4b 00 73 00 [0-2] 50 00 73 00 44 00 68 00 47 00 4d 00 78 00 49 00 50 00 42 00 5a 00 77 00 57 00 79 00 67 00 [0-2] 70 00 61 00 56 00 69 00 6f 00 54 00 55 00 59 00 53 00 77 00 6b 00 6f 00 68 00 42 00 42 00 [0-2] 7a 00 5a 00 76 00 41 00 66 00 7a 00 4f 00 73 00 78 00 62 00 41 00 6e 00 48 00 67 00 51 00}  //weight: 5, accuracy: Low
        $x_5_2 = {47 5a 56 58 64 54 4b 7a 7a 74 69 6b 69 4a 4c [0-2] 4d 78 68 57 7a 79 6f 59 4f 70 67 6e 62 63 69 [0-2] 69 50 7a 68 48 73 46 57 70 6c 58 63 48 4b 73 [0-2] 50 73 44 68 47 4d 78 49 50 42 5a 77 57 79 67 [0-2] 70 61 56 69 6f 54 55 59 53 77 6b 6f 68 42 42 [0-2] 7a 5a 76 41 66 7a 4f 73 78 62 41 6e 48 67 51}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

