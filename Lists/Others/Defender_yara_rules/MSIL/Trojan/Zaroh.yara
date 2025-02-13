rule Trojan_MSIL_Zaroh_A_2147708880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zaroh.A"
        threat_id = "2147708880"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zaroh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 00 7c 00 52 00 61 00 68 00 6f 00 7a 00 7c 00 7e 00 ?? ?? 77 00 69 00 6e 00 64 00 69 00 72 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 00 69 00 64 00 64 00 65 00 6e 00 ?? ?? 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 ?? ?? 2f 00 44 00 65 00 6c 00 65 00 74 00 65 00 20 00 2f 00 54 00 4e 00 20 00 22 00 55 00 70 00 64 00 61 00 74 00 65 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5b 00 4c 00 4f 00 43 00 41 00 54 00 49 00 4f 00 4e 00 5d 00 ?? ?? 5b 00 55 00 53 00 45 00 52 00 49 00 44 00 5d 00 ?? ?? 2f 00 43 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 54 00 4e 00 20 00 22 00 55 00 70 00 64 00 61 00 74 00 65 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 ?? ?? 52 00 65 00 67 00 41 00 73 00 6d 00 2e 00 65 00 78 00 65 00 ?? ?? 52 00 65 00 67 00 53 00 76 00 63 00 73 00 2e 00 65 00 78 00 65 00 ?? ?? 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = {5c 00 52 00 75 00 6e 00 22 00 20 00 2f 00 66 00 20 00 2f 00 76 00 20 00 22 00 ?? ?? 22 00 20 00 2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 53 00 5a 00 20 00 2f 00 64 00 20 00 22 00 ?? ?? 43 00 6c 00 61 00 73 00 73 00 4c 00 69 00 62 00 72 00 61 00 72 00 79 00 31 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

