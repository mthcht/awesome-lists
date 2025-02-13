rule Trojan_Win64_DarkShellLoader_LK_2147850042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DarkShellLoader.LK!MTB"
        threat_id = "2147850042"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DarkShellLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d1 e8 03 c2 c1 e8 05 0f b7 c0 6b c8 37 41 0f b7 c0 66 2b c1 66 83 c0 36 66 41 31 01 41 ff c0 4d 8d 49 02 41 83 f8 10 7c ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

