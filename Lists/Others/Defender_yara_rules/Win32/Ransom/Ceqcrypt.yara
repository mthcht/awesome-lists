rule Ransom_Win32_Ceqcrypt_A_2147712057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ceqcrypt.A"
        threat_id = "2147712057"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceqcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 65 00 6e 00 63 00 00 00 12 00 00 00 5c 00 6a 00 61 00 76 00 61 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 5f 00 65 00 6e 00 63 00 00 00 [0-16] 61 00 70 00 70 00 64 00 61 00 74 00 61 00}  //weight: 1, accuracy: Low
        $x_1_3 = {00 6a 00 61 00 32 00 00 [0-48] 50 00 4f 00 57 00 45 00 52 00 43 00 46 00 47 00 20 00 2f 00 53 00 45 00 54 00 41 00 43 00 54 00 49 00 56 00 45 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

