rule Trojan_Win64_SysDon_A_2147848711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SysDon.A"
        threat_id = "2147848711"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SysDon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 5c 24 ?? 48 89 7c 24 ?? e8 be 01 00 00 48 8b 8d ?? ?? 00 00 8b d8 e8 c4 34 00 00 48 83 a5 78 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

