rule Trojan_Win64_AuKill_B_2147906404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AuKill.B"
        threat_id = "2147906404"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AuKill"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5b 2d 5d 20 45 78 63 65 70 74 20 69 6e 20 4b 69 6c 6c 50 72 ?? 63 65 73 73 48 61 6e 64 6c 65 73}  //weight: 1, accuracy: Low
        $x_1_2 = {5b 21 5d 20 4f 70 65 6e 50 72 6f 63 65 73 73 54 6f 6b 65 6e 20 66 61 69 6c 65 64 20 28 54 72 75 ?? 74 65 64 49 6e 73 74 61 6c 6c 65 72 2e 65 78 65 29 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

