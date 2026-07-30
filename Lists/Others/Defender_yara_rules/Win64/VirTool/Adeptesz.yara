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
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 45 18 ba 27 00 00 00 48 89 c1 e8 ?? ?? ?? ?? 48 8b 45 e0 8b 10 48 8b 45 18 48 89 c1 e8 ?? ?? ?? ?? 48 8b 45 18 ba 0a 00 00 00 48 89 c1 e8 ?? ?? ?? ?? 48 8b 45 10 8b 55 ec 48 63 d2 48 89 c1 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 00 4c 8b 88 88 02 00 00 48 8b 45 e0 48 8b 40 10 ?? ?? ?? ?? 49 89 d0 ba 7f 66 04 40 48 89 c1 ?? ?? ?? 89 45 d8 83 7d d8 ff ?? ?? ?? ?? ?? ?? 8b 45 9c 83 f8 03}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 45 fc 24 06 00 00 ?? ?? 83 7d f8 40 ?? ?? 83 7d f8 5a ?? ?? 83 45 f8 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

