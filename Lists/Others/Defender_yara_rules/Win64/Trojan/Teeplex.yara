rule Trojan_Win64_Teeplex_A_2147705662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Teeplex.A"
        threat_id = "2147705662"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Teeplex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 f0 4d 0f b1 bc f1 ?? ?? ?? ?? 48 8b d8 74 0e 48 3b c7 0f 84}  //weight: 1, accuracy: Low
        $x_1_2 = {41 8b c1 41 ff c1 41 f7 f2 42 0f b6 04 1a 41 2a 40 ff 41 88 40 ff 44 3b ?? 72 df}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

