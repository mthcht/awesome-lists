rule Trojan_Win32_Svcfake_A_2147616653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Svcfake.A"
        threat_id = "2147616653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Svcfake"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 65 74 73 76 63 73 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 54 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 68 6f 73 74}  //weight: 1, accuracy: High
        $x_1_2 = {50 6f 72 74 61 62 6c 65 20 4e 75 6d 62 65 72 20 53 65 72 76 69 63 65 00 73 79 73 74 65 6d 64 6f 77 6e}  //weight: 1, accuracy: High
        $x_1_3 = "Lka%d_%d.dll" ascii //weight: 1
        $x_1_4 = {49 6e 73 74 61 6c 6c 4d 6f 64 75 6c 65 00 00 00 52 65 6d 6f 74 65 20 41 63 63 65 73 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

