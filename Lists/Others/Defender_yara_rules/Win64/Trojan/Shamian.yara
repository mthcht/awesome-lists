rule Trojan_Win64_Shamian_A_2147777393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shamian.A!dha"
        threat_id = "2147777393"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shamian"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID:" ascii //weight: 1
        $x_1_2 = "main.XorDecodeStr" ascii //weight: 1
        $x_1_3 = "main.init" ascii //weight: 1
        $x_1_4 = "/miansha/xx2.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

