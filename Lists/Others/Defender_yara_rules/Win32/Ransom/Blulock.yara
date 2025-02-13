rule Ransom_Win32_Blulock_A_2147694621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Blulock.A"
        threat_id = "2147694621"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Blulock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 69 6e 4c 6f 63 6b 44 6c 6c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {54 61 73 6b 4d 61 6e 61 67 65 72 5f 45 6e 61 62 6c 65 5f 44 69 73 61 62 6c 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {54 61 73 6b 53 77 69 74 63 68 69 6e 67 5f 45 6e 61 62 6c 65 5f 44 69 73 61 62 6c 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {41 6c 74 54 61 62 32 5f 45 6e 61 62 6c 65 5f 44 69 73 61 62 6c 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 62 6c 75 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

