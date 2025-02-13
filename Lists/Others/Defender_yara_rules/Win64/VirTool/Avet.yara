rule VirTool_Win64_Avet_15_2147844679_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Avet.15!MTB"
        threat_id = "2147844679"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Avet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 e0 48 89 c3 b8 00 01 00 00 48 98 48 83 e8 01 48 89 45 f8 b8 00 01 00 00 48 98 48 89 c6 bf 00 00 00 00 b8 00 01 00 00 48 98 49 89 c2 41 bb 00 00 00 00 b8 00 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 81 e9 00 10 00 00 48 83 09 00 48 2d 00 10 00 00 48 3d 00 10 00 00 77 e7}  //weight: 1, accuracy: High
        $x_1_3 = {44 8b 45 38 48 8b 4d 50 48 8b 55 30 48 8b 45 f0 45 89 c1 49 89 c8 48 89 c1 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

