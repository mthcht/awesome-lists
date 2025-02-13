rule Ransom_Win32_Cribit_A_2147685908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cribit.A"
        threat_id = "2147685908"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cribit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {42 69 74 63 6f 6d 69 6e 74 00 00 00 ff ff ff ff 0c 00 00 00 62 69 74 63 72 79 70 74 2e 63 63 77}  //weight: 5, accuracy: High
        $x_5_2 = {69 6e 66 65 63 74 65 64 20 62 79 20 42 69 74 43 72 79 70 74 20 76 [0-1] 2e [0-1] 20 63 72 79 70 74 6f 76 69 72 75 73 2e 00}  //weight: 5, accuracy: Low
        $x_5_3 = "more information you should find txt file named Bitcrypt.txt on your hard drive." ascii //weight: 5
        $x_5_4 = {63 6d 64 2e 65 78 65 00 2f 4b 20 62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 62 6f 6f 74 73 74 61 74 75 73 70 6f 6c 69 63 79 20 69 67 6e 6f 72 65 61 6c 6c 66 61 69 6c 75 72 65 73 00}  //weight: 5, accuracy: High
        $x_1_5 = {42 69 74 43 72 79 70 74 2e 62 6d 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

