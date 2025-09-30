rule Trojan_Win64_MagicScald_A_2147953619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MagicScald.A"
        threat_id = "2147953619"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MagicScald"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce 49 83 c0 04 49 83 c2 04 83 e1 07 8b c3 ff c6 41 33 c5 2b c7 8b fb 41 89 40 fc d3 c7 49 ff c9}  //weight: 1, accuracy: High
        $x_1_2 = {8b c2 33 c1 d1 e9 a8 01 ?? ?? 81 f1 20 83 b8 ed}  //weight: 1, accuracy: Low
        $x_1_3 = "c:\\test\\tgsreq1.bin" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

