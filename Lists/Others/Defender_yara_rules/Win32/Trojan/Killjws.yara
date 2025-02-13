rule Trojan_Win32_Killjws_A_2147600276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killjws.A"
        threat_id = "2147600276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killjws"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {42 49 4e 00 6a 73 74 72 69 6e 67 73 00 2e 74 6d 70 2e 65 78 65 00 4a 53 54 52 49 4e 47 53 00 57 53 54 52 49 4e 47 53 00 31 00 2a 2e 2a 00 5c 00 65 78 65 00 74 6d 70 62 69 6e 64 2e 65 78 65 00 2e 00 2e 2e 00 74 65 6d 70 00 74 65 6d 70 6f 72 61 72 79 20 69 6e 74 65 72 6e 65 74 20 66 69 6c 65 73 00 61 70 70 6c 69 63 61 74 69 6f 6e 20 64 61 74 61 00 5c 6d 63 69 33 32 2e 65 78 65 00 00 00 00 00 00 ff ff ff ff 4d 5a 90 00 03 00 00 00 04 00 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killjws_A_2147600276_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killjws.A"
        threat_id = "2147600276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killjws"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {41 73 79 6e 63 68 72 6f 6e 6f 75 73 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 4e 6f 74 69 66 79 5c 00 44 6c 6c 4e 61 6d 65 00 69 6d 70 65 72 73 6f 6e 61 74 65 00 73 74 61 72 74 75 70 00 53 74 61 72 74 75 70 00 6c 6f 67 6f 6e 00 4c 6f 67 6f 6e 00 43 6f 6d 6f 64 6f 20 41 6e 74 69 2d 56 69 72 75 73 20 61 6e 64 20 41 6e 74 69 2d 53 70 79 77 61 72 65 20 53 65 72 76 69 63 65 00 74 65 65 66 65 72 00 53 6d 63 53 65 72 76 69 63 65 00 61 76 67 66 77 73 72 76 00 42 44 46}  //weight: 10, accuracy: High
        $x_10_2 = {61 74 65 00 73 79 6d 6e 64 69 73 00 4a 65 74 69 63 6f 20 50 65 72 73 6f 6e 61 6c 20 46 69 72 65 77 61 6c 6c 20 73 65 72 76 65 72 00 76 66 69 6c 74 00 74 6d 70 66 77 00 6c 6e 73 66 77 31 00 44 69 73 61 62 6c 65 53 52 00 53 4f 46 54 57 41 52 45 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 53 79 73 74 65 6d 52 65 73 74 6f 72 65 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 4e 6f 74 69 66 79 5c 73 65 63 75 72 69 74 79 53 65 72 76 69 63 65 00 64 6c 6c 6e 61 6d 65 00 73 65 63 75 72 69 74 79 53 65 72 76 69 63 65 2e 64 6c 6c 00 30 00 62 6c 61 68 00 61 73}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

