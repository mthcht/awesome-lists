rule VirTool_WinNT_Bunitu_A_2147605013_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Bunitu.A"
        threat_id = "2147605013"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Bunitu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3a b8 7c 1b 0f b6 52 01 bb ?? ?? 01 00 83 3d ?? ?? 01 00 00 75 09 87 1c 90 89 1d ?? ?? 01 00 b8 ?? ?? 01 00 8b 40 01 8b 30 8b d6 bf ?? ?? 01 00 b9 0d 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

