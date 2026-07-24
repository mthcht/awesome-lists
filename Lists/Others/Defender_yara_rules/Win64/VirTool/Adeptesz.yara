rule VirTool_Win64_Adeptesz_A_2147974409_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Adeptesz.A"
        threat_id = "2147974409"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Adeptesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 45 18 ba 27 00 00 00 48 89 c1 e8 ?? ?? ?? ?? 48 8b 45 e0 8b 10 48 8b 45 18 48 89 c1 e8 ?? ?? ?? ?? 48 8b 45 18 ba 0a 00 00 00 48 89 c1 e8 ?? ?? ?? ?? 48 8b 45 10 8b 55 ec 48 63 d2 48 89 c1 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 45 e0 48 8b 40 08 ?? ?? ?? ?? ?? ?? ?? ?? 49 89 c8 48 89 c1 e8 ?? ?? ?? ?? 89 45 d4 83 7d d4 ff ?? ?? 48 8b 45 18 ba 00 00 00 00 48 89 c1 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

