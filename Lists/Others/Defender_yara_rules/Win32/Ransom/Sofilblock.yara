rule Ransom_Win32_Sofilblock_A_2147664118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sofilblock.A"
        threat_id = "2147664118"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sofilblock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2a 2e 62 6c 6f 63 6b [0-21] 2e 64 65 63 72 79 70 74}  //weight: 1, accuracy: Low
        $x_1_2 = {2a 2e 77 72 69 [0-16] 2a 2e 63 73 73 [0-16] 2a 2e 61 73 6d [0-16] 2a 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {46 69 6c 65 73 6f 70 2e 74 78 74 2e 62 6c 6f 63 6b [0-16] 62 67 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 10 ff 12 f7 d8 83 d2 00 f7 da 52 50 b2 01 8b c6 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

