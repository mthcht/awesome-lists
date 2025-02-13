rule Trojan_MSIL_Mubuie_A_2147696839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mubuie.A"
        threat_id = "2147696839"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mubuie"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {04 4c 6f 61 64 00 00 39 01 00 34 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 64 6f 77 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {25 41 70 70 44 61 74 61 25 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 42 74 68 48 46 53 72 76 00}  //weight: 1, accuracy: High
        $x_1_3 = {67 65 74 5f 53 65 74 74 69 6e 67 31 00 73 65 74 5f 53 65 74 74 69 6e 67 31 00 67 65 74 5f 53 65 74 74 69 6e 67 32 00 73 65 74 5f 53 65 74 74 69 6e 67 32 00}  //weight: 1, accuracy: High
        $x_1_4 = "6b6b2a92-7ca3-4491-9718-09b1e5e728e0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

