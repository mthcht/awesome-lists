rule Ransom_Win64_Cryptolocker_MKV_2147926085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Cryptolocker.MKV!MTB"
        threat_id = "2147926085"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 33 c1 29 41 78 48 8b 0d ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? 33 41 28 83 f0 23 89 41 28 8b 0d ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? 05 7f 8c 01 00 03 c8 8b 05 ?? ?? ?? ?? 33 05 c7 ac 1d 00 89 0d}  //weight: 5, accuracy: Low
        $x_4_2 = {8b 02 41 2b c1 31 05 ?? ?? ?? ?? b8 80 75 78 00 2b c1 01 82 9c 00 00 00 8b 0d f2 ac 1d 00 01 0d ?? ?? ?? ?? 48 81 fb 80 b3 1a 00 0f 8c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

