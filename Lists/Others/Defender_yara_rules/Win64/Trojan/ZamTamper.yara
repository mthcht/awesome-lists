rule Trojan_Win64_ZamTamper_A_2147933896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZamTamper.A"
        threat_id = "2147933896"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZamTamper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7a 00 61 00 6d 00 36 00 34 00 2e 00 73 00 79 00 73 00 00 00 2d 00 2d 00 6c 00 6f 00 6f 00 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {5a 00 61 00 6d 00 6d 00 4f 00 63 00 69 00 64 00 65 00 00 00 2d 00 2d 00 70 00 69 00 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {46 61 69 6c 65 64 20 74 6f 20 74 65 72 6d 69 6e 61 74 65 20 70 72 6f 63 65 73 73 ?? ?? 46 61 69 6c 65 64 20 74 6f 20 6c 6f 61 64 20 64 72 69 76 65 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

