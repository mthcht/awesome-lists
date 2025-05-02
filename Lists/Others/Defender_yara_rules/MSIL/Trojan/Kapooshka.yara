rule Trojan_MSIL_Kapooshka_A_2147940539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kapooshka.A!dha"
        threat_id = "2147940539"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kapooshka"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 6f 6d 6d 61 6e 64 44 65 73 63 72 69 70 74 6f 72 00 63 6f 6d 6d 61 6e 64 ?? 65 73 63 72 69 70 74 6f 72 00 45 78 65 63 75 74 6f 72 00 65 78 65 ?? 75 74 6f 72 00}  //weight: 1, accuracy: Low
        $x_1_2 = {43 6f 6d 6d 61 6e 64 46 61 63 74 6f 72 79 00 63 6f 6d 6d 61 6e 64 ?? 61 63 74 6f 72 79 00 42 72 6f 77 73 65 72 54 65 6c 65 6d 65 74 72 79 00 47 65 74 46 72 6f 6d 52 ?? 67 69 73 74 72 79 00}  //weight: 1, accuracy: Low
        $x_1_3 = {73 65 74 5f 43 72 65 61 74 65 4e 6f ?? 69 6e 64 6f 77 00 47 65 74 43 6f 6d 6d 61 6e 64 42 79 00 64 65 6c 61 79 00 41 72 72 61 79 00}  //weight: 1, accuracy: Low
        $x_1_4 = {49 43 6f 6d 6d 61 6e 64 00 67 65 74 5f 43 6f 6d ?? 61 6e 64 00 73 65 74 5f 43 6f 6d 6d 61 6e 64 00 44 6f 77 6e 6c 6f 61 64 43 6f 6d 6d 61 6e 64 00 55 70 6c 6f 61 64 ?? 6f 6d 6d 61 6e 64 00}  //weight: 1, accuracy: Low
        $x_1_5 = {41 64 64 43 6f 6d 6d 61 6e 64 00 45 78 65 43 6f ?? 6d 61 6e 64 00 4b 69 6c 6c 43 6f 6d 6d 61 6e 64 00 43 6c 65 61 72 43 6f ?? 6d 61 6e 64 00 54 69 6d 65 6f 75 74 43 6f 6d 6d 61 6e 64 00}  //weight: 1, accuracy: Low
        $x_1_6 = {73 65 74 5f 52 65 73 75 6c 74 00 43 6f 6d 6d 61 6e 64 52 65 73 ?? 6c 74 00 43 68 65 63 6b 56 61 6c 69 64 61 74 69 6f 6e 52 65 73 75 6c 74 00 73 65 74 5f 55 73 ?? 72 41 67 65 6e 74 00}  //weight: 1, accuracy: Low
        $x_1_7 = {41 62 6f 72 74 00 49 73 43 6f 6d 6d 61 6e ?? 49 73 46 61 73 74 00 48 74 74 70 57 65 62 52 65 71 75 65 73 74 00 53 65 6e 64 47 65 ?? 52 65 71 75 65 73 74 00}  //weight: 1, accuracy: Low
        $x_1_8 = {50 61 72 73 65 43 6f 6d 6d 61 6e 64 73 00 45 78 65 63 75 74 65 ?? 6f 6e 67 43 6f 6d 6d 61 6e 64 73 00 6c 6f 6e 67 43 6f 6d 6d 61 6e 64 73 00 67 65 74 ?? 54 6f 74 61 6c 53 65 63 6f 6e 64 73 00}  //weight: 1, accuracy: Low
        $x_1_9 = {47 65 74 50 48 50 53 65 73 73 49 64 00 53 74 61 72 74 53 ?? 70 61 72 61 74 65 54 68 72 65 61 64 00 6c 6f 6e 67 43 6f 6d 6d 61 6e 64 73 54 68 72 65 61 64 00 70 61 79 ?? 6f 61 64 00}  //weight: 1, accuracy: Low
        $x_1_10 = {47 65 74 45 6e 75 6d 65 72 61 74 6f 72 00 2e 63 74 6f 72 00 53 65 72 76 65 72 49 6e 66 ?? 45 78 74 72 61 63 74 6f 72 00 2e 63 63 74 6f 72 00 4d 6f 6e 69 74 6f 72 00 43 6f 6d 6d 61 6e 64 44 65 73 ?? 72 69 70 74 6f 72 00}  //weight: 1, accuracy: Low
        $x_1_11 = {6c 6f 6e 67 43 6f 6d 6d 61 6e 64 73 ?? 68 72 65 61 64 00 70 61 79 6c 6f 61 64 00 41 64 64 00 53 65 74 50 72 6f 78 79 49 66 4e 65 65 64 65 64 00}  //weight: 1, accuracy: Low
        $x_1_12 = {67 65 74 5f 50 72 6f 78 79 00 73 65 74 5f 50 72 6f 78 79 00 49 57 65 62 50 ?? 6f 78 79 00 70 72 6f 78 79 00 43 6d 53 65 72 76 69 63 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f ?? 72 63 65 73 00}  //weight: 1, accuracy: Low
        $x_1_13 = {73 65 74 5f 55 73 65 44 65 66 61 75 6c 74 43 72 ?? 64 65 6e 74 69 61 6c 73 00 70 68 70 73 65 73 73 69 64 53 79 6d 62 6f 6c 73 00 42 72 6f 77 73 65 72 54 65 6c 65 6d 65 74 72 79 2e 43 6f 6e 6e 65 63 ?? 69 6f 6e 73 00 67 65 74 5f 43 68 61 72 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

