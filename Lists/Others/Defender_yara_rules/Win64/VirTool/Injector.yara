rule VirTool_Win64_Injector_SA_2147899377_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Injector.SA"
        threat_id = "2147899377"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {b8 6b 00 00 00 66 89 84 24 ?? 01 00 00 b8 65 00 00 00 66 89 84 24 ?? 01 00 00 b8 72 00 00 00 66 89 84 24 ?? 01 00 00 b8 6e 00 00 00}  //weight: 3, accuracy: Low
        $x_2_2 = {66 00 00 00 c7 44 24 48 0c 09 3d 00}  //weight: 2, accuracy: High
        $x_1_3 = {48 c7 84 24 ?? 01 00 00 00 00 00 00 48 c7 84 24 ?? 01 00 00 00 00 00 00 48 c7 84 24 ?? 01 00 00 00 00 00 00 c6 44 24 70}  //weight: 1, accuracy: Low
        $x_1_4 = {ba 6e 09 1a 00}  //weight: 1, accuracy: High
        $x_1_5 = {ba 56 0c 38 00}  //weight: 1, accuracy: High
        $x_1_6 = {ba 56 60 0d 00}  //weight: 1, accuracy: High
        $x_1_7 = {ba c6 9e 46 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

