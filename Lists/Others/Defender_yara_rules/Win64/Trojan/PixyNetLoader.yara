rule Trojan_Win64_PixyNetLoader_AL_2147981256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PixyNetLoader.AL!MTB"
        threat_id = "2147981256"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PixyNetLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b d3 80 e1 07 c0 e1 03 48 d3 ea 43 32 94 30 ?? ?? ?? ?? 42 88 54 04 30 4c 03 c6 49 83}  //weight: 1, accuracy: Low
        $x_2_2 = {80 e1 03 c0 e1 04 48 d3 ea 66 43 33 94 46 ?? ?? ?? ?? 66 42 89 54 44 60 4c 03 c6 49 83}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

