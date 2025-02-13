rule Trojan_MSIL_Delhost_A_2147731184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Delhost.A"
        threat_id = "2147731184"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Delhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 74 61 72 74 73 57 69 74 68 00 62 79 70 61 73 73 41 63 6c 43 68 65 63 6b}  //weight: 1, accuracy: High
        $x_1_2 = {5b 00 7b 00 30 00 7d 00 5d 00 00 03 2d 00 01 05 5c 00 5c 00 00 05 3a 00 5c 00 00 23 53 00 65 00 42 00 61 00 63 00 6b 00 75 00 70 00 50 00 72 00 69 00 76 00 69 00 6c 00 65 00 67 00 65 00 00 25 53 00 65 00 52 00 65 00 73 00 74 00 6f 00 72 00 65 00 50 00 72 00 69 00 76 00 69 00 6c 00 65 00 67 00 65 00 00 31 53 00 65 00 54 00 61 00 6b 00 65 00 4f 00 77 00 6e 00 65 00 72 00 73 00 68 00 69 00 70 00 50 00 72 00 69 00 76 00 69 00 6c 00 65 00 67 00 65 00 00 27 53 00 65 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 50 00 72 00 69 00 76 00 69 00 6c 00 65 00 67 00 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {7b 00 31 00 7d 00 00 05 2d 00 73 00 01 19 2d 00 2d 00 73 00 69 00 6c 00 65 00 6e 00 74 00 4d 00 6f 00 64 00 65 00 01 17 2d 00 2d 00 62 00 79 00 70 00 61 00 73 00 73 00 41 00 63 00 6c 00 01 23 2d 00 2d 00 70 00 72 00 69 00 6e 00 74 00 53 00 74 00 61 00 63 00 6b 00 54 00 72 00 61 00 63 00 65 00 01 09 74 00 65 00 78 00 74 00 00 81 3d 20}  //weight: 1, accuracy: High
        $x_1_4 = "Done. Deleted {0} files and {1} folders in {2}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

