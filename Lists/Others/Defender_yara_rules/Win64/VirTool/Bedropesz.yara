rule VirTool_Win64_Bedropesz_A_2147921766_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Bedropesz.A!MTB"
        threat_id = "2147921766"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Bedropesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 0d 30 43 0a 00 [0-33] 48 89 85 a8 05 00 00 48 83 bd a8 05 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 0d dc 42 0a 00 ?? ?? ?? ?? ?? 41 b8 06 00 00 00 ba 01 00 00 00 b9 02 00 00 00 48 8b 05 34 ac 0c 00 ?? ?? 48 89 85 a0 05 00 00 48 83 bd a0 05 00 00 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 85 a0 05 00 00 48 89 c1 48 8b 05 d1 aa 0c 00 [0-20] 48 8b 0d 98 41 0a 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ba 00 04 00 00 49 89 d0 ba 00 00 00 00 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 8d a0 05 00 00 41 b9 00 00 00 00 41 b8 00 04 00 00 48 89 c2 48 8b 05 9d aa 0c 00}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 0d 12 41 0a 00 ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? 48 89 c2 ?? ?? ?? ?? ?? 48 8b 15 07 41 0a 00 48 89 c1 [0-19] 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

