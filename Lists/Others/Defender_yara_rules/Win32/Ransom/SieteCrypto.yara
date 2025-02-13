rule Ransom_Win32_SieteCrypto_A_2147711945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SieteCrypto.A"
        threat_id = "2147711945"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SieteCrypto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 73 2e 5f 25 30 32 69 2d 25 30 32 69 2d 25 30 32 69 2d 25 30 32 69 2d 25 30 32 69 2d 25 30 32 69 5f 24 25 73 24 2e ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {25 73 3f 69 70 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {40 00 53 00 79 00 73 00 74 00 65 00 6d 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 6f 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {50 00 72 00 65 00 73 00 73 00 20 00 4f 00 4b 00 20 00 74 00 6f 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "Demo version works till" wide //weight: 1
        $x_1_7 = "\\read_this_file.txt" wide //weight: 1
        $x_1_8 = {37 00 5c 00 74 00 6d 00 70 00 2e 00 62 00 6d 00 70 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

