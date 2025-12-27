rule VirTool_Win64_Genpck_A_2147954593_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Genpck.A"
        threat_id = "2147954593"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Genpck"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5d 68 fa 3c [0-4] 8b}  //weight: 5, accuracy: Low
        $x_5_2 = {5b bc 4a 6a 0f 85}  //weight: 5, accuracy: High
        $x_1_3 = {48 81 c4 f0 00 00 00 41 5e 5f 5e 5b 5d c3}  //weight: 1, accuracy: High
        $x_1_4 = {48 81 c4 d8 07 00 00 41 5f 41 5e 41 5d 41 5c 5f 5e 5b 5d c3}  //weight: 1, accuracy: High
        $x_1_5 = {49 8b ce ff ?? ?? ?? ?? ?? 48 8b d3 48 8b ce 41 ff d6 85 c0 48 0f 4f de 48 03 f5 48 3b f7 76 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

