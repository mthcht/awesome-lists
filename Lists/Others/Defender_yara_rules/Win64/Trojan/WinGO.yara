rule Trojan_Win64_Wingo_MA_2147846018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Wingo.MA!MTB"
        threat_id = "2147846018"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Wingo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 83 ec 60 48 89 6c 24 58 48 8d 6c 24 58 83 3d ?? ?? ?? ?? 02 ?? 0f 84 ?? ?? ?? ?? 48 85 c0 0f 84 ?? ?? ?? ?? 88 4c 24 78 48 89 5c 24 70 80 3d 65 f4 20 00 00 ?? 0f 84 80}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

