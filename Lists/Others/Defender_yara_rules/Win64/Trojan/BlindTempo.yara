rule Trojan_Win64_BlindTempo_A_2147965142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlindTempo.A"
        threat_id = "2147965142"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlindTempo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c9 41 b8 00 10 00 00 44 8d 49 04 ff}  //weight: 1, accuracy: High
        $x_1_2 = {c7 44 24 58 73 be 47 b0 c7 44 24 5c df 70 b9 4c c7 44 24 60 c8 f3 8d 44}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

