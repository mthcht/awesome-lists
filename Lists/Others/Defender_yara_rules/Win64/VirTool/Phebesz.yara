rule VirTool_Win64_Phebesz_A_2147981493_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Phebesz.A"
        threat_id = "2147981493"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Phebesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 44 24 68 [0-16] 41 8b cd e8 ?? ?? ?? ?? 85 c0 [0-22] e8 ?? ?? ?? ?? 41 8b d5 48 8b c8 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be 03 66 89 01 ?? ?? ?? ?? ?? ?? ?? ?? 48 83 ea 01 ?? ?? 48 89 75 d0 66 45 89 3c 70 48 8b 75 d8 48 8b 5d d0 [0-20] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

