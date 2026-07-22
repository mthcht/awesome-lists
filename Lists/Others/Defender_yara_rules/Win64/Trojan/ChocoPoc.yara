rule Trojan_Win64_ChocoPoc_A_2147974282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ChocoPoc.A!AMTB"
        threat_id = "2147974282"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ChocoPoc"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 49 8d 42 01 49 f7 f1 49 8b c0 49 8b c8 48 c1 e9 08 83 e0 07 41 32 c8 44 32 d9 41 8a cb 41 c0 e3 02 c0 e9 05 41 0a cb 32 0c 2a 33 d2 41 32 0c 2a 49 83 c2 0d 41 30 0c 30 49 03 c2 49 f7 f1 49 ff c0 44 8a d9 4c 8b d2 4c 3b c7 72 b2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

