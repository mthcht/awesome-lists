rule VirTool_Win64_Rediresz_A_2147959257_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Rediresz.A"
        threat_id = "2147959257"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Rediresz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b f8 48 85 c0 [0-19] 48 8b c8 ff ?? ?? ?? ?? ?? 48 89 05 1f f9 03 00 ?? ?? ?? ?? ?? ?? ?? 48 8b cf ff ?? ?? ?? ?? ?? 48 89 05 00 f9 03 00 49 8b 56 08 83 fb 02 ?? ?? ?? ?? ?? ?? 33 c9 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 5c 24 28 89 5c 24 20 33 d2 33 c9 ff ?? ?? ?? ?? ?? 8b d8 85 c0 [0-22] e8 ?? ?? ?? ?? 48 8b 08 48 63 51 04 81 64 02 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

