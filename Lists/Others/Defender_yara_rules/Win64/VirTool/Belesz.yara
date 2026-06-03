rule VirTool_Win64_Belesz_A_2147970842_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Belesz.A"
        threat_id = "2147970842"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Belesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 56 57 48 83 ec 40 ?? ?? ?? ?? ?? 48 c7 45 f8 fe ff ff ff 48 89 d7 48 89 ce c7 45 f4 00 00 00 00 ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 39 7d f4 ?? ?? 48 89 f1 31 d2 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {55 48 83 ec 40 ?? ?? ?? ?? ?? 48 c7 45 f8 fe ff ff ff b9 32 00 00 00 ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 89 c2 ?? ?? ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

