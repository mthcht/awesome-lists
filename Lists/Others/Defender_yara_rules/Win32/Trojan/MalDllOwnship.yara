rule Trojan_Win32_MalDllOwnship_Z_2147967016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MalDllOwnship.Z!MTB"
        threat_id = "2147967016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MalDllOwnship"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 00 61 00 6b 00 65 00 6f 00 77 00 6e 00 [0-15] 2f 00 66 00 [0-6] 63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 [0-6] 2f 00 61 00}  //weight: 1, accuracy: Low
        $x_1_2 = {74 00 61 00 6b 00 65 00 6f 00 77 00 6e 00 [0-15] 2f 00 66 00 [0-6] 63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6e 00 74 00 64 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00 [0-6] 2f 00 61 00}  //weight: 1, accuracy: Low
        $x_1_3 = {74 00 61 00 6b 00 65 00 6f 00 77 00 6e 00 [0-15] 2f 00 66 00 [0-6] 63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 61 00 64 00 76 00 61 00 70 00 69 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 [0-6] 2f 00 61 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

