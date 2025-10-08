rule VirTool_Win64_Depringesz_A_2147954521_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Depringesz.A!MTB"
        threat_id = "2147954521"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Depringesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 0f b6 ce c0 e9 04 41 2a c7 40 c0 e6 04 41 83 c5 03 40 c0 e5 02 40 0a e9 88 44 24 7b 40 0f b6 cf 42 88 2c 22 c0 e9 02 40 0a ce 40 c0 e7 06 40 0a f8}  //weight: 1, accuracy: High
        $x_1_2 = {4c 8b 74 24 28 48 8b 6c 24 50 4c 8b bc 24 88 00 00 00 45 85 ed [0-20] 8b 4c 24 70 49 8b d4 4d 63 c5 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

