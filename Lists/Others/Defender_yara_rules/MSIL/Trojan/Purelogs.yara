rule Trojan_MSIL_Purelogs_HHE_2147935339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Purelogs.HHE!MTB"
        threat_id = "2147935339"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Purelogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 06 04 6f ?? 00 00 0a 73 ?? 00 00 0a 0b 07 20 ?? 1c 00 00 28 ?? 02 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 07 20 ?? 1b 00 00 28 ?? 02 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 07 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0c de 1b}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Purelogs_PGP_2147940787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Purelogs.PGP!MTB"
        threat_id = "2147940787"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Purelogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 00 37 00 39 00 2e 00 34 00 33 00 2f 00 70 00 61 00 6e 00 65 00 6c 00 2f 00 70 00 61 00 6e 00 65 00 6c 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73}  //weight: 1, accuracy: High
        $x_4_2 = {52 00 65 00 61 00 64 00 41 00 73 00 42 00 79 00 74 00 65 00 41 00 72 00 72 00 61 00 79 00 41 00 73 00 79 00 6e 00 63 00 00 11 47 00 65 00 74 00 41 00 73 00 79 00 6e 00 63}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Purelogs_PGPL_2147962941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Purelogs.PGPL!MTB"
        threat_id = "2147962941"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Purelogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {63 f8 e8 3f 6c 82 c9 4e 41 7a 2d 7f 91 7a b4 5b 1f fb 4b c6 71 18 d6 bb b8 90 9c 0f fb 51 d4 55 ea 83 14 2a 6f 85 cb 21 94 d6 95 ea 59 a5 28 f1 67 6e b0 1b 54 35 41 da 46 8f 50 bf 02 6e 5d 6f 0a 2a 87 e7 10 f9 2e d6 f7 5e ee a2 3b 29 34 30 c2 7e 73 54 be 10 ed 79 39 c6 64 44 6a 47 18 93 05 e6 8b ef 2f da}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

