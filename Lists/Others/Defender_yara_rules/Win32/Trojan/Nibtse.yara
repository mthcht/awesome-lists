rule Trojan_Win32_Nibtse_A_2147734631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nibtse.A"
        threat_id = "2147734631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nibtse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 68 00 74 00 61 00 [0-8] 20 00 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 61 00 77 00 2f 00 2f 10 10 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nibtse_A_2147734631_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nibtse.A"
        threat_id = "2147734631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nibtse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "schtasks /create /tn " wide //weight: 1
        $x_1_2 = {20 00 2f 00 74 00 72 00 20 00 6d 00 73 00 68 00 74 00 61 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 29 03 03 00 2e 00 29 03 03 00 2e 00 29 03 03 00 2e 00 29 03 03 00 3a 00 29 05 05 00 2f 00 [0-32] 20 00 2f 00 73 00 63 00 20 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nibtse_A_2147734631_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nibtse.A"
        threat_id = "2147734631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nibtse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 [0-5] 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = "mshta vbscript:CreateObject" wide //weight: 1
        $x_1_3 = ".Run(" wide //weight: 1
        $x_1_4 = "//pastebin.com/raw/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nibtse_A_2147734631_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nibtse.A"
        threat_id = "2147734631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nibtse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 [0-5] 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = " /sc MINUTE " wide //weight: 1
        $x_1_3 = {20 00 2f 00 74 00 72 00 20 00 6d 00 73 00 68 00 74 00 61 00 [0-8] 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 61 00 77 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_4 = {20 00 2f 00 74 00 72 00 20 00 6d 00 73 00 68 00 74 00 61 00 [0-8] 20 00 68 00 74 00 74 00 70 00 3a 00 5c 00 5c 00 70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00 5c 00 72 00 61 00 77 00 5c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Nibtse_A_2147734631_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nibtse.A"
        threat_id = "2147734631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nibtse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 68 00 74 00 61 00 20 00 76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 57 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 29 00 2e 00 52 00 75 00 6e 00 28 00 6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 20 00 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 61 00 77 00 2f 00 2f 10 10 00 2c 00 30 00 2c 00 74 00 72 00 75 00 65 00 29 00 28 00 77 00 69 00 6e 00 64 00 6f 00 77 00 2e 00 63 00 6c 00 6f 00 73 00 65 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 00 6d 00 73 00 68 00 74 00 61 00 2e 00 45 00 58 00 45 00 20 00 76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 57 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 29 00 2e 00 52 00 75 00 6e 00 28 00 6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 20 00 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 61 00 77 00 2f 00 2f 10 10 00 2c 00 30 00 2c 00 74 00 72 00 75 00 65 00 29 00 28 00 77 00 69 00 6e 00 64 00 6f 00 77 00 2e 00 63 00 6c 00 6f 00 73 00 65 00 29 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

