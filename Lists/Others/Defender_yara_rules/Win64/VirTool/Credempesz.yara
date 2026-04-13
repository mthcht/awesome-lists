rule VirTool_Win64_Credempesz_A_2147966879_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Credempesz.A"
        threat_id = "2147966879"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Credempesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 db 0f 11 45 f0 ff ?? ?? ?? ?? ?? c7 00 16 00 00 00 ff [0-16] e8 ?? ?? ?? ?? 48 85 db [0-20] 48 8b d3 ?? ?? ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 44 24 20 4d 8b cd [0-18] e8 ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? 4c 8b 64 24 30 49 8b d4 ?? ?? ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

