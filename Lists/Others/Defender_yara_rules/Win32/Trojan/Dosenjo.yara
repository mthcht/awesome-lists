rule Trojan_Win32_Dosenjo_A_145058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dosenjo.A"
        threat_id = "145058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dosenjo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 94 8a 4c 0d 98 30 08 ff 45 94 83 7d 94 20 72 04 83 65 94 00 40 80 38 00 75 e4}  //weight: 1, accuracy: High
        $x_1_2 = {00 73 76 63 64 6c 6c ?? 2e 64 6c 6c 00 53 74 72 74 50 72 63 00}  //weight: 1, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 00 00 6b 65 72 6e 65 6c 33 32 00 00 00 00 25 73 5c 25 73 00 00 00 63 73 72 73 73 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

