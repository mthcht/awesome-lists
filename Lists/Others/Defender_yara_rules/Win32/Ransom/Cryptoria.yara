rule Ransom_Win32_Cryptoria_A_2147696744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryptoria.A"
        threat_id = "2147696744"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptoria"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 79 5f 50 72 6f 67 72 61 6d 5f 41 6c 72 65 61 64 79 5f 50 72 65 73 65 6e 74 00}  //weight: 1, accuracy: High
        $x_2_2 = {5c 63 72 79 70 74 74 72 6f 5c 52 65 6c 65 61 73 65 5c 63 72 79 70 74 74 72 6f 2e 70 64 62 00}  //weight: 2, accuracy: High
        $x_1_3 = {25 73 5c 25 73 2e 64 65 63 72 79 70 74 6d 79 40 69 6e 64 69 61 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_2_4 = {25 73 5c 68 65 6c 70 2d 64 65 63 72 79 70 74 2d 66 69 6c 65 2e 65 6e 63 00}  //weight: 2, accuracy: High
        $x_2_5 = {25 73 5c 73 69 63 72 65 74 6b 65 79 2e 65 6e 63 00}  //weight: 2, accuracy: High
        $x_1_6 = "-----BEGIN PUBLIC KEY-----MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

