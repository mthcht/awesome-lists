rule Ransom_Win32_Krybit_A_2147970585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Krybit.A"
        threat_id = "2147970585"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Krybit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 61 6e 27 74 20 6f 70 65 6e 20 66 69 6c 65 20 61 66 74 65 72 20 6b 69 6c 6c 48 6f 6c 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {52 00 45 00 43 00 4f 00 56 00 45 00 52 00 2d 00 52 00 45 00 41 00 44 00 4d 00 45 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {2e 00 4b 00 52 00 59 00 42 00 49 00 54 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

