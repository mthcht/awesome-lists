rule Ransom_Win32_Pagongcrypt_A_2147711700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Pagongcrypt.A"
        threat_id = "2147711700"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Pagongcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Encrypted.dat" ascii //weight: 1
        $x_1_2 = "\\Microsoft\\TrueCrypter\\" ascii //weight: 1
        $x_1_3 = {5c 00 52 00 75 00 6e 00 [0-8] 54 00 72 00 75 00 65 00 43 00 72 00 79 00 70 00 74 00 65 00 72 00}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 52 75 6e [0-8] 54 72 75 65 43 72 79 70 74 65 72}  //weight: 1, accuracy: Low
        $x_2_5 = "Config/Infos/Encrypted" ascii //weight: 2
        $x_2_6 = {2f 00 43 00 20 00 63 00 68 00 6f 00 69 00 63 00 65 00 20 00 2f 00 43 00 20 00 59 00 20 00 2f 00 4e 00 20 00 2f 00 44 00 20 00 59 00 20 00 2f 00 54 00 20 00 31 00 20 00 26 00 20 00 44 00 65 00 6c 00 [0-8] 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 [0-8] 2f 00 53 00 74 00 61 00 74 00 75 00 73 00 2e 00 70 00 68 00 70 00}  //weight: 2, accuracy: Low
        $x_2_7 = {2f 43 20 63 68 6f 69 63 65 20 2f 43 20 59 20 2f 4e 20 2f 44 20 59 20 2f 54 20 31 20 26 20 44 65 6c [0-8] 63 6d 64 2e 65 78 65 [0-8] 2f 53 74 61 74 75 73 2e 70 68 70}  //weight: 2, accuracy: Low
        $x_2_8 = {2e 00 65 00 6e 00 63 00 [0-8] 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 43 00 72 00 79 00 70 00 74 00 6f 00 [0-8] 2f 00 54 00 72 00 61 00 6e 00 73 00 61 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 70 00 68 00 70 00}  //weight: 2, accuracy: Low
        $x_2_9 = {2e 65 6e 63 [0-8] 5c 4d 69 63 72 6f 73 6f 66 74 5c 43 72 79 70 74 6f [0-8] 2f 54 72 61 6e 73 61 63 74 69 6f 6e 2e 70 68 70}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

