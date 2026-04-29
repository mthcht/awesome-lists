rule Trojan_Win32_SuspDllOwnship_ZA_2147967017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspDllOwnship.ZA!MTB"
        threat_id = "2147967017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspDllOwnship"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 00 63 00 61 00 63 00 6c 00 73 00 [0-15] 63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 [0-6] 2f 00 67 00 72 00 61 00 6e 00 74 00 [0-6] 61 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 73 00 3a 00 28 00 66 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {69 00 63 00 61 00 63 00 6c 00 73 00 [0-15] 63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6e 00 74 00 64 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00 [0-6] 2f 00 67 00 72 00 61 00 6e 00 74 00 [0-6] 61 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 73 00 3a 00 28 00 66 00 29 00}  //weight: 1, accuracy: Low
        $x_1_3 = {69 00 63 00 61 00 63 00 6c 00 73 00 [0-15] 63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 61 00 64 00 76 00 61 00 70 00 69 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 [0-6] 2f 00 67 00 72 00 61 00 6e 00 74 00 [0-6] 61 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 73 00 3a 00 28 00 66 00 29 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_SuspDllOwnship_ZB_2147967018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspDllOwnship.ZB!MTB"
        threat_id = "2147967018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspDllOwnship"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 00 63 00 61 00 63 00 6c 00 73 00 [0-15] 63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 [0-6] 2f 00 64 00 65 00 6e 00 79 00 [0-6] 6e 00 74 00 20 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 5c 00 77 00 69 00 6e 00 64 00 65 00 66 00 65 00 6e 00 64 00 3a 00 28 00 72 00 78 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {69 00 63 00 61 00 63 00 6c 00 73 00 [0-15] 63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 [0-6] 2f 00 64 00 65 00 6e 00 79 00 [0-6] 6e 00 74 00 20 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 5c 00 63 00 79 00 73 00 65 00 72 00 76 00 65 00 72 00 3a 00 28 00 72 00 78 00 29 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

