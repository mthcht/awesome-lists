rule Trojan_Win64_GoRat_MV_2147890437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoRat.MV!MSR"
        threat_id = "2147890437"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoRat"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 6c 6c 6f 63 41 6c 6c 00 30 30 4f 4f 30 30 4f 4f 4f 4f 4f 4f 30 4f 30 4f 4f 00 30 4f 30 30 30 30 30 6f 4f 30 30 30 6f 4f 4f 30 4f 30 4f 6f 00 6f 30 4f 4f 6f 30 30 6f 4f 4f 4f 30 30 30 30 30 4f 30 4f 6f 00 30 4f 30 30 30 6f 30 6f 6f 30 4f 4f 6f 4f 6f 4f 30 00 72 75 6e 74 69 6d 65 2e 28 2a 62 75 63 6b 65 74 29 2e 73 74 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

