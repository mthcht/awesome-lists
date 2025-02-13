rule Trojan_Win32_Modimer_A_2147726279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Modimer.A"
        threat_id = "2147726279"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Modimer"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 6f 73 68 61 6e 2e 62 69 74 2f 73 74 61 72 74 2e 70 68 70 00 68 74 74 70 3a 2f 2f 67 6f 73 68 61 6e 2e 6f 6e 6c 69 6e 65 2f 73 74 61 72 74 2e 70 68 70 00 00 68 74 74 70 3a 2f 2f 6d 65 64 69 61 2d 67 65 74 2e 62 69 74 2f 73 74 61 72 74 2e 70 68 70 00 00 68 74 74 70 3a 2f 2f 6d 65 64 6c 61 2d 67 65 74 2e 63 6f 6d 2f 73 74 61 72 74 2e}  //weight: 1, accuracy: High
        $x_1_2 = {2f 6d 79 2e 64 61 74 00 52 55 4e 00 48 41 53 48}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

