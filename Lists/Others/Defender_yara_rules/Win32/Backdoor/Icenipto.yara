rule Backdoor_Win32_Icenipto_A_2147624363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Icenipto.A"
        threat_id = "2147624363"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Icenipto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {49 00 63 00 65 00 50 00 6f 00 69 00 6e 00 74 00 2e 00 65 00 78 00 65 00 00 00 0c 00 00 00 77 00 69 00 6e 00 64 00 69 00 72}  //weight: 10, accuracy: High
        $x_10_2 = {66 00 79 00 68 00 77 00 34 00 6b 00 37 00 34 00 68 00 72 00 2e 00 65 00 78 00 65 00 00 00 02 00 00 00 5c 00 00 00 08 00 00 00 2e 00 65 00 78 00 65 00 00 00 00 00 16 00 00 00 43 00 3a 00 5c 00 6b 00 69 00 6c 00 6c 00 2e 00 62 00 61 00 74 00 00 00 0c 00 00 00 3a 00 72 00 65 00 64 00 65 00 6c 00}  //weight: 10, accuracy: High
        $x_10_3 = {64 00 72 00 69 00 76 00 65 00 72 00 2e 00 69 00 6e 00 66 00 00 00 1a 00 00 00 5c 00 49 00 50 00 64 00 72 00 69 00 76 00 65 00 72 00 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: High
        $x_1_4 = "state: [ all attack stopped ]" wide //weight: 1
        $x_1_5 = {52 00 45 00 53 00 45 00 54 00 00 00 1c 00 00 00 5c 00 56 00 69 00 64 00 65 00 6f 00 43 00 61 00 72 00 64 00 2e 00 65 00 78 00 65 00 00 00 00 00 0e 00 00 00 45 00 78 00 65 00 63 00 75 00 74 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

