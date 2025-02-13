rule Trojan_Win64_DuckTailImage_LKA_2147895766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DuckTailImage.LKA!MTB"
        threat_id = "2147895766"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DuckTailImage"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 15 e0 eb 30 00 4c 0f b6 c1 4c 8d 0d 41 ec 30 00 4c 8b d0 49 83 e2 0f 4f 0f b6 0c 11 46 88 0c 02 48 c1 e8 04 80 e9 01 48 85 c0 75 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

