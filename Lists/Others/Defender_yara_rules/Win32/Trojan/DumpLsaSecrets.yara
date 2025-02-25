rule Trojan_Win32_DumpLsaSecrets_ZPA_2147934404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DumpLsaSecrets.ZPA"
        threat_id = "2147934404"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsaSecrets"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 00 65 00 67 00 [0-10] 20 00 73 00 61 00 76 00 65 00 20 00 48 00 4b 00 4c 00 4d 00 5c 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 5c 00 70 00 6f 00 6c 00 69 00 63 00 79 00 5c 00 73 00 65 00 63 00 72 00 65 00 74 00 73 00}  //weight: 1, accuracy: Low
        $x_1_2 = {72 00 65 00 67 00 [0-10] 20 00 73 00 61 00 76 00 65 00 20 00 68 00 6b 00 65 00 79 00 5f 00 6c 00 6f 00 63 00 61 00 6c 00 5f 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 5c 00 70 00 6f 00 6c 00 69 00 63 00 79 00 5c 00 73 00 65 00 63 00 72 00 65 00 74 00 73 00}  //weight: 1, accuracy: Low
        $x_1_3 = {72 00 65 00 67 00 [0-10] 20 00 65 00 78 00 70 00 6f 00 72 00 74 00 20 00 48 00 4b 00 4c 00 4d 00 5c 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 5c 00 70 00 6f 00 6c 00 69 00 63 00 79 00 5c 00 73 00 65 00 63 00 72 00 65 00 74 00 73 00}  //weight: 1, accuracy: Low
        $x_1_4 = {72 00 65 00 67 00 [0-10] 20 00 65 00 78 00 70 00 6f 00 72 00 74 00 20 00 68 00 6b 00 65 00 79 00 5f 00 6c 00 6f 00 63 00 61 00 6c 00 5f 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 5c 00 70 00 6f 00 6c 00 69 00 63 00 79 00 5c 00 73 00 65 00 63 00 72 00 65 00 74 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

