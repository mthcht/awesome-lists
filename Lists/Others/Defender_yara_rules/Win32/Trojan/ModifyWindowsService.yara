rule Trojan_Win32_ModifyWindowsService_AD_2147941895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ModifyWindowsService.AD"
        threat_id = "2147941895"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ModifyWindowsService"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 20 00 28 00 47 00 65 00 74 00 2d 00 57 00 6d 00 69 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 77 00 69 00 6e 00 33 00 32 00 5f 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 2d 00 66 00 69 00 6c 00 74 00 65 00 72 00 [0-80] 49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 57 00 6d 00 69 00 4d 00 65 00 74 00 68 00 6f 00 64 00 20 00 2d 00 4e 00 61 00 6d 00 65 00 20 00 43 00 68 00 61 00 6e 00 67 00 65 00 20 00 2d 00 41 00 72 00 67 00 75 00 6d 00 65 00 6e 00 74 00 4c 00 69 00 73 00 74 00}  //weight: 3, accuracy: Low
        $x_3_2 = {20 00 40 00 28 00 24 00 6e 00 75 00 6c 00 6c 00 2c 00 20 00 24 00 6e 00 75 00 6c 00 6c 00 2c 00 20 00 24 00 6e 00 75 00 6c 00 6c 00 2c 00 20 00 24 00 6e 00 75 00 6c 00 6c 00 2c 00 20 00 24 00 6e 00 75 00 6c 00 6c 00 2c 00 [0-4] 41 00 74 00 74 00 61 00 63 00 6b 00 49 00 51 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

