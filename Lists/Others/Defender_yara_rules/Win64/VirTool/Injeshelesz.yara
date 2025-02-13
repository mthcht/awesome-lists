rule VirTool_Win64_Injeshelesz_A_2147924242_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Injeshelesz.A!MTB"
        threat_id = "2147924242"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Injeshelesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 15 09 aa 00 00 48 8b 05 da 69 00 00 49 89 d0 48 89 c2 [0-18] 48 8b 05 e9 a9 00 00 c7 44 24 20 40 00 00 00 41 b9 00 30 00 00 41 b8 15 00 00 00 ba 00 00 00 00 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 05 cd a9 00 00 48 8b 05 8e 69 00 00 41 b8 15 00 00 00 48 89 c2 [0-18] 48 8b 15 aa a9 00 00 48 8b 05 93 a9 00 00 48 c7 44 24 20 00 00 00 00 41 b9 15 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 05 42 69 00 00 41 b8 15 00 00 00 48 89 c2 [0-18] 48 8b 05 5e a9 00 00 48 89 c1 48 8b 05 44 a9 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 54 24 30 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 49 89 c9 41 b8 00 00 00 00 ba 00 00 00 00 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 45 18 48 83 c0 08 48 8b 00 48 89 c1 ?? ?? ?? ?? ?? 89 05 8d aa 00 00 8b 15 87 aa 00 00 48 8b 05 68 6a 00 00 41 89 d0 48 89 c2 [0-18] 8b 05 68 aa 00 00 41 89 c0 ba 00 00 00 00 b9 ff 0f 1f 00}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b 0d ba a8 00 00 8b 15 a8 a8 00 00 48 8b 05 7d 68 00 00 49 89 c9 41 89 d0 48 89 c2 [0-18] 48 8b 05 91 a8 00 00 ba ff ff ff ff 48 89 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

