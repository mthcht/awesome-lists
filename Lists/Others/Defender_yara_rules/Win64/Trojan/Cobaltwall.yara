rule Trojan_Win64_Cobaltwall_A_2147982758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobaltwall.A"
        threat_id = "2147982758"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltwall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 00 47 00 56 00 73 00 62 00 47 00 38 00 3d 00 00 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {63 00 68 00 72 00 6f 00 6d 00 65 00 75 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00 00 00 5f 00 65 00 6e 00 74 00 72 00 79 00 2e 00 70 00 79 00}  //weight: 1, accuracy: High
        $x_1_3 = {77 74 73 61 70 69 33 32 2e 64 6c 6c 00 49 73 49 6e 74 65 72 61 63 74 69 76 65 55 73 65 72 53 65 73 73 69 6f 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

