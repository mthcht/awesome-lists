rule Trojan_Win32_DisableIntegrity_A_2147938681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DisableIntegrity.A!ibt"
        threat_id = "2147938681"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DisableIntegrity"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {62 00 63 00 64 00 65 00 64 00 69 00 74 00 2e 00 65 00 78 00 65 00 [0-4] 2d 00 73 00 65 00 74 00 [0-4] 6e 00 6f 00 69 00 6e 00 74 00 65 00 67 00 72 00 69 00 74 00 79 00 63 00 68 00 65 00 63 00 6b 00 73 00 [0-4] 79 00 65 00 73 00 [0-4] 26 00}  //weight: 10, accuracy: Low
        $x_10_2 = {62 00 63 00 64 00 65 00 64 00 69 00 74 00 2e 00 65 00 78 00 65 00 [0-4] 2d 00 73 00 65 00 74 00 [0-4] 74 00 65 00 73 00 74 00 73 00 69 00 67 00 6e 00 69 00 6e 00 67 00 [0-4] 79 00 65 00 73 00 [0-4] 26 00}  //weight: 10, accuracy: Low
        $x_10_3 = {62 00 63 00 64 00 65 00 64 00 69 00 74 00 2e 00 65 00 78 00 65 00 [0-4] 2d 00 73 00 65 00 74 00 [0-4] 6e 00 78 00 [0-4] 61 00 6c 00 77 00 61 00 79 00 73 00 6f 00 66 00 66 00 [0-4] 26 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

