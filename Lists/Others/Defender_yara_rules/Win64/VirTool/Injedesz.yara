rule VirTool_Win64_Injedesz_A_2147967498_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Injedesz.A"
        threat_id = "2147967498"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Injedesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8b 44 24 38 33 d2 b9 10 00 00 00 ff ?? ?? ?? ?? ?? 48 8b d8 48 85 c0 ?? ?? 45 33 c0 48 8b d0 49 8b cf ff ?? ?? ?? ?? ?? 85 c0 ?? ?? 8b 54 24 38}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 8b 05 b4 41 00 00 41 b9 00 30 00 00 33 d2 c7 44 24 20 04 00 00 00 49 8b ce ff ?? ?? ?? ?? ?? 4c 8b f8 48 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {49 8b cf ff [0-16] 49 8b d7 ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 4c 8b 0d 5e 40 00 00 ?? ?? ?? ?? ?? ?? ?? 4c 8b 05 48 40 00 00 49 8b d7 49 8b ce 48 89 44 24 20 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

