rule Ransom_Win32_ZCryptor_A_2147712132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ZCryptor.A"
        threat_id = "2147712132"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ZCryptor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 52 65 6c 65 61 73 65 5c 4d 79 45 6e 63 72 79 70 74 65 72 32 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_2 = {7a 63 72 79 70 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 48 6f 77 20 74 6f 20 64 65 63 72 79 70 74 20 66 69 6c 65 73 2e 68 74 6d 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = "ALL YOUR PERSONAL FILES ARE ENCRYPTED</font></p>" ascii //weight: 1
        $x_1_5 = "[How To Decrypt Your Files]<" ascii //weight: 1
        $x_1_6 = {61 75 74 6f 72 75 6e 2e 69 6e 66 00}  //weight: 1, accuracy: High
        $x_1_7 = {0f 1f 44 00 00 8d 41 2e 30 44 0d e4 41 83 f9 0b 72 f3 8d 45 e4 c6 45 ef 00 50 68 04 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

