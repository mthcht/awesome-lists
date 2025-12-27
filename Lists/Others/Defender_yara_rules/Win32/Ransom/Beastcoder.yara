rule Ransom_Win32_Beastcoder_YBH_2147950101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Beastcoder.YBH!MTB"
        threat_id = "2147950101"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Beastcoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 56 57 6a 17 8d 71 04 5b 8a 16 8b 01 32 c2 88 06 46 83 eb 01}  //weight: 1, accuracy: High
        $x_1_2 = {33 c0 80 2c 08 08 40 83 f8 17}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

