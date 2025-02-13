rule Trojan_MSIL_Heraclez_A_2147922417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heraclez.A!MTB"
        threat_id = "2147922417"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heraclez"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 54 6f 53 74 72 69 6e 67 00 45 78 69 74 00 41 64 64 72 65 73 73 46 61 6d 69 6c 79 00 53 6f 63 6b 65 74 54 79 70 65 00 50 72 6f 74 6f 63 6f 6c 54 79 70 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 00 4a 6f 69 6e 00 49 6e 74 33 32 00 42 6f 6f 6c 65 61 6e 00 49 73 4e 75 6c 6c 4f 72 45 6d 70 74 79 00 4c 6f 61 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

