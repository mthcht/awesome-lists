rule Trojan_Win32_DisableRemoteReg_A_2147921885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DisableRemoteReg.A"
        threat_id = "2147921885"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DisableRemoteReg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 00 65 00 67 00 [0-8] 20 00 61 00 64 00 64 00 20 00}  //weight: 5, accuracy: Low
        $x_1_2 = {68 00 6b 00 6c 00 6d 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 70 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 6e 00 74 00 5c 00 74 00 65 00 72 00 6d 00 69 00 6e 00 61 00 6c 00 20 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 [0-2] 20 00 2f 00 76 00 20 00 64 00 69 00 73 00 61 00 62 00 6c 00 65 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 73 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 6b 00 6c 00 6d 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 5c 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 73 00 65 00 74 00 5c 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 74 00 65 00 72 00 6d 00 69 00 6e 00 61 00 6c 00 20 00 73 00 65 00 72 00 76 00 65 00 72 00 5c 00 77 00 69 00 6e 00 73 00 74 00 61 00 74 00 69 00 6f 00 6e 00 73 00 5c 00 72 00 64 00 70 00 2d 00 74 00 63 00 70 00 [0-2] 20 00 2f 00 76 00 20 00 75 00 73 00 65 00 72 00 61 00 75 00 74 00 68 00 65 00 6e 00 74 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

