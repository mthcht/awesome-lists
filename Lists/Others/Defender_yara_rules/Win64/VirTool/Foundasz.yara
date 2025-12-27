rule VirTool_Win64_Foundasz_A_2147955442_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Foundasz.A"
        threat_id = "2147955442"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Foundasz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 10 48 8b 45 f8 48 89 c1 ?? ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 48 85 c0 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? b8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 55 18 48 89 02 48 8b 45 18 48 8b 00 48 85 c0 ?? ?? 48 8b 45 10 48 89 c2 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? b8 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

