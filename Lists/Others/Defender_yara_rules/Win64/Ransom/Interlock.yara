rule Ransom_Win64_Interlock_D_2147968378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Interlock.D"
        threat_id = "2147968378"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Interlock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 6d 64 20 2f 63 20 66 73 75 74 69 6c 20 62 65 68 61 76 69 6f 72 20 73 65 74 20 53 79 6d 6c 69 6e 6b 45 76 61 6c 75 61 74 69 6f 6e 20 52 32 4c 3a 31 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 63 68 74 61 73 6b 73 20 2f 64 65 6c 65 74 65 20 2f 74 6e 20 54 61 73 6b 53 79 73 74 65 6d 20 2f 66 20 3e 20 6e 75 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {2e 21 6e 2b 65 72 6c 6f 63 6b 00}  //weight: 1, accuracy: High
        $x_1_4 = {5f 5f 52 45 41 44 2d 2d 42 45 46 4f 52 45 2d 2d 41 4e 59 54 48 49 4e 47 5f 5f 2e 74 78 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

