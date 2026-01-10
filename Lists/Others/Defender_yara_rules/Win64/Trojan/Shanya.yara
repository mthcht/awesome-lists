rule Trojan_Win64_Shanya_A_2147960924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shanya.A"
        threat_id = "2147960924"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shanya"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 77 6d 73 67 61 70 69 2e 57 6d 73 67 42 72 6f 61 64 63 61 73 74 4d 65 73 73 61 67 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {0f be c8 81 c1 ?? ?? ?? ?? 45 6b c0 1f 48 ff c2 8a 02 44 33 c1}  //weight: 1, accuracy: Low
        $x_1_3 = {9c 66 81 0c 24 00 01 9d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

