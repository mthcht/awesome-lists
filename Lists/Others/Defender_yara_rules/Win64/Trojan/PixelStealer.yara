rule Trojan_Win64_PixelStealer_LR_2147965916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PixelStealer.LR!MTB"
        threat_id = "2147965916"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PixelStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 c1 e8 39 4d 8d 41 f0 49 21 d0 42 88 04 09 42 88 44 01 10 48 8b 45 00 48 8d 0c bf 48 89 c2 48 29 ca 4c 8b 44 24 38 4f 8d 0c 89}  //weight: 20, accuracy: High
        $x_10_2 = {49 29 c8 49 89 d1 49 29 c9 4d 31 c1 49 21 e9 49 83 f9 10 0f 82 ?? ?? ?? ?? 48 8d 0c 92 44 0f b6 04 16 48 c1 e8 39 4c 8d 4a f0 49 21 e9 88 04 16}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

