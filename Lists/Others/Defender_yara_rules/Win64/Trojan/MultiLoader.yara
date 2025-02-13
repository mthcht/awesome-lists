rule Trojan_Win64_MultiLoader_A_2147906403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MultiLoader.A"
        threat_id = "2147906403"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MultiLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c8 48 8b d8 48 63 78 ?? 48 03 f8 48 8b d7 e8 ?? ?? ?? ?? 8b 57 28 48 03 d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

