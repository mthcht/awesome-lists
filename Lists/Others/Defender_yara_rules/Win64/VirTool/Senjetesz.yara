rule VirTool_Win64_Senjetesz_A_2147955144_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Senjetesz.A"
        threat_id = "2147955144"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Senjetesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 53 48 83 ec 40 48 c7 44 24 30 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? c7 44 24 28 80 00 00 00 45 33 c9 45 33 c0 c7 44 24 20 01 00 00 00 ba 00 00 00 40 ?? ?? ?? ?? ?? ?? 48 8b d8 48 83 f8 ff ?? ?? ?? ?? ?? ?? ?? ?? 8b d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

