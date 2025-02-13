rule Trojan_Win64_PortStarter_A_2147920291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PortStarter.A"
        threat_id = "2147920291"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PortStarter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6d 61 78 20 70 6f 72 74 20 66 6f 72 20 6c 69 ?? 74 65 6e 20 74 6f}  //weight: 2, accuracy: Low
        $x_1_2 = {6d 61 69 6e 2e 64 6c 6c 00 54 65 73 74 00 5f 63 67 6f 5f 64 75 6d 6d 79 ?? 65 78 70 6f 72 74}  //weight: 1, accuracy: Low
        $x_1_3 = {6b 75 69 4e 65 77 20 70 ?? 72 74 3a 20 25 73 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

