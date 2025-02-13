rule Trojan_MSIL_Pony_KAY_2147924327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Pony.KAY!MTB"
        threat_id = "2147924327"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pony"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {77 2b 40 67 4c 7d f9 6f 6a 4a 5f 4d 46 67 46 37 55 68 6a 3a 5f 42 46 67 46 c5 52 68}  //weight: 3, accuracy: High
        $x_4_2 = {b3 3b 53 68 6a 4e 68 5b dc 74 4a 54 40 48 fd d4 0f 36 1c 47 01 4e cd b0 0b 72 29 b4}  //weight: 4, accuracy: High
        $x_5_3 = {7f 4d 74 e0 0f d3 9e 6f 6d 61 6c b3 14 6e ad 6f 51 72 80 9a b3 ba 2a 6e 6a 4a 73 38 79}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

