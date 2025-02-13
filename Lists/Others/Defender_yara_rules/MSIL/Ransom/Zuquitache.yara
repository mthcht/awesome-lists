rule Ransom_MSIL_Zuquitache_A_2147707813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Zuquitache.A"
        threat_id = "2147707813"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zuquitache"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 00 69 00 20 00 42 00 75 00 64 00 64 00 79 00 21 00 00 0f 6d 00 65 00 73 00 73 00 61 00 67 00 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "/READ_ME_FOR_DECRYPT.txt" ascii //weight: 1
        $x_1_3 = "/READ ME FOR DECRYPT.txt" ascii //weight: 1
        $x_1_4 = {2f 00 52 00 45 00 41 00 44 00 5f 00 4d 00 45 00 2e 00 74 00 78 00 74 00 ?? ?? 61 00 6d 00 6f 00 75 00 6e 00 74 00}  //weight: 1, accuracy: Low
        $x_2_5 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 00 0f 74 00 61 00 73 00 6b 00 6d 00 67 00 72 00 00 0f 2e 00 6c 00 6f 00 63 00 6b 00 65 00 64 00}  //weight: 2, accuracy: High
        $x_3_6 = {62 00 74 00 63 00 3d 00 00 0b 26 00 77 00 69 00 64 00 3d 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

