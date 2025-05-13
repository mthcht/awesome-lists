rule Trojan_Win64_RandomPhrase_A_2147941209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RandomPhrase.A"
        threat_id = "2147941209"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RandomPhrase"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 40 48 89 75 f8 48 89 f1 48 81 c1 ?? ?? 00 00 e8 ?? ?? ?? ?? 48 89 c6 48 89 05 ?? ?? ?? ?? e8 05 00 00 00 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

