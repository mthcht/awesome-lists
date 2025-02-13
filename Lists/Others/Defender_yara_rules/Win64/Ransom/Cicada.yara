rule Ransom_Win64_Cicada_DB_2147924190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Cicada.DB"
        threat_id = "2147924190"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Cicada"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 69 6e 5f 65 6e 63 [0-2] 72 75 6e 5f 63 6f 6d 6d 61 6e 64}  //weight: 1, accuracy: Low
        $x_1_2 = {77 69 6e 5f 65 6e 63 [0-2] 63 6f 6c 6c 65 63 74 5f 66 69 6c 65 73 5f 65 78 63 65 70 74 5f 72 65 63 75 72 73 69 76 65 6c 79}  //weight: 1, accuracy: Low
        $x_1_3 = {77 69 6e 5f 65 6e 63 [0-2] 77 72 69 74 65 5f 61 6e 64 5f 65 78 65 63 75 74 65 5f 62 61 74 63 68}  //weight: 1, accuracy: Low
        $x_1_4 = {77 69 6e 5f 65 6e 63 [0-2] 67 65 74 5f 76 61 6c 69 64 5f 64 72 69 76 65 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

