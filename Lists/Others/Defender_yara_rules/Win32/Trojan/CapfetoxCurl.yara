rule Trojan_Win32_CapfetoxCurl_A_2147822735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CapfetoxCurl.A"
        threat_id = "2147822735"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CapfetoxCurl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 75 00 72 00 6c 00 [0-255] 20 00 2d 00 68 00 20 00 [0-6] 78 00 2d 00 61 00 70 00 69 00 2d 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 3a 00 [0-6] 24 00 7b 00 6a 00 6e 00 64 00 69 00 3a 00 6c 00 64 00 61 00 70 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_2 = {63 00 75 00 72 00 6c 00 [0-255] 20 00 2d 00 68 00 20 00 [0-6] 78 00 2d 00 61 00 70 00 69 00 2d 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 3a 00 [0-6] 24 00 7b 00 6a 00 6e 00 64 00 69 00 3a 00 72 00 6d 00 69 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_3 = {63 00 75 00 72 00 6c 00 [0-255] 20 00 2d 00 68 00 20 00 [0-6] 78 00 2d 00 61 00 70 00 69 00 2d 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 3a 00 [0-6] 24 00 7b 00 6a 00 6e 00 64 00 69 00 3a 00 6c 00 64 00 61 00 70 00 73 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_4 = {63 00 75 00 72 00 6c 00 [0-255] 20 00 2d 00 68 00 20 00 [0-6] 78 00 2d 00 61 00 70 00 69 00 2d 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 3a 00 [0-6] 24 00 7b 00 6a 00 6e 00 64 00 69 00 3a 00 64 00 6e 00 73 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_5 = {63 00 75 00 72 00 6c 00 [0-255] 20 00 2d 00 68 00 20 00 [0-6] 78 00 2d 00 61 00 70 00 69 00 2d 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 3a 00 [0-6] 24 00 7b 00 6a 00 6e 00 64 00 69 00 3a 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_6 = {63 00 75 00 72 00 6c 00 [0-255] 20 00 2d 00 68 00 20 00 [0-6] 78 00 2d 00 61 00 70 00 69 00 2d 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 3a 00 [0-6] 24 00 7b 00 6a 00 6e 00 64 00 69 00 3a 00 69 00 69 00 6f 00 70 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

