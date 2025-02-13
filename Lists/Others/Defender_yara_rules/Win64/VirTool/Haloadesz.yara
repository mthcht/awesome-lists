rule VirTool_Win64_Haloadesz_A_2147852612_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Haloadesz.A!MTB"
        threat_id = "2147852612"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Haloadesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 8f 0a 87 06 f3 0f 7f 45 e0 c7 45 d0 eb ce dc cb c7 45 d4 da c3 99 98 c6 45 d8 aa 66 c7 45 f0 98 aa e8 ?? ?? ?? ?? ba 01 8f 35 06 48 8b c8 e8 ?? ?? ?? ?? 48 89 05 3e 45 00 00 48 ?? ?? ?? 41}  //weight: 1, accuracy: Low
        $x_1_2 = {80 71 ff aa 83 c2 09 80 31 aa 80 71 01 aa 80 71 02 aa 80 71 03 aa 80 71 04 aa 80 71 05 aa 80 71 06 aa 80 71 07 aa 48 ?? ?? ?? 83}  //weight: 1, accuracy: Low
        $x_1_3 = {49 8b ce e8 ?? ?? ?? ?? 48 8b c8 4c 8b d8 e8 ?? ?? ?? ?? 49 8b cb 44 0f b7 d0 e8 ?? ?? ?? ?? 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

