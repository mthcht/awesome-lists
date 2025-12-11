rule VirTool_Win64_Geisesz_A_2147959254_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Geisesz.A"
        threat_id = "2147959254"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Geisesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 5c 24 40 48 8b 4c 24 48 48 c7 c7 ff ff ff ff 0f b7 74 24 3e 44 0f b7 44 24 3c 41 89 c1 48 8b 44 24 58 ?? ?? ?? ?? e8 [0-17] bb 12 00 00 00 31 c9 31 ff 48 83 c4}  //weight: 1, accuracy: Low
        $x_1_2 = {55 48 89 e5 48 81 ec b0 01 00 00 ?? ?? ?? e8 ?? ?? ?? ?? 48 85 c0 ?? ?? 48 89 84 24 88 00 00 00 44 0f 11 bc 24 10 01 00 00 44 0f 11 bc 24 20 01 00 00 31 c9 31 d2 31 db 31 f6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

