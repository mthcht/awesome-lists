rule Ransom_Win32_Eniqma_A_2147711707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Eniqma.A"
        threat_id = "2147711707"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Eniqma"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 00 52 00 53 00 41 00 [0-8] 45 00 4e 00 49 00 47 00 4d 00 41 00 5f 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 52 53 41 [0-8] 45 4e 49 47 4d 41 5f}  //weight: 1, accuracy: Low
        $x_1_3 = {43 00 72 00 79 00 70 00 74 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 20 00 6f 00 6e 00 65 00 21 00 [0-16] 43 00 72 00 79 00 70 00 74 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 20 00 45 00 72 00 72 00 6f 00 72 00 21 00 21 00 [0-16] 65 00 72 00 72 00 20 00 77 00 72 00 69 00 74 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {43 72 79 70 74 45 6e 63 72 79 70 74 20 6f 6e 65 21 [0-16] 43 72 79 70 74 45 6e 63 72 79 70 74 20 45 72 72 6f 72 21 21 [0-16] 65 72 72 20 77 72 69 74 65}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 00 65 00 6e 00 69 00 67 00 6d 00 61 00 [0-8] 3a 00 5c 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_6 = {2e 65 6e 69 67 6d 61 [0-8] 3a 5c 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

