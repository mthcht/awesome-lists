rule VirTool_Win64_Pesenesz_A_2147966880_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Pesenesz.A"
        threat_id = "2147966880"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Pesenesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 c7 44 24 30 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? c7 44 24 28 00 00 00 00 45 33 c9 45 33 c0 c7 44 24 20 03 00 00 00 ba 00 00 00 c0 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 c7 44 24 38 00 00 00 00 ?? ?? ?? ?? ?? ba 10 e0 22 00 48 8b cb ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 30 ?? ?? ?? ?? ?? c7 44 24 28 10 00 00 00 48 89 44 24 20 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {ba 10 00 00 00 ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 0f 57 c0 ?? ?? ?? ?? ?? ?? ?? 0f 11 44 24 58 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

