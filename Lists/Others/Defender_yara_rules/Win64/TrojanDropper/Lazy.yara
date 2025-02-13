rule TrojanDropper_Win64_Lazy_CCJR_2147922861_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Lazy.CCJR!MTB"
        threat_id = "2147922861"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 41 b8 08 02 00 00 48 8d 4d c0 e8 ?? ?? ?? ?? ba 04 01 00 00 48 8d 4d c0 ff 15}  //weight: 1, accuracy: Low
        $x_2_2 = {48 63 41 04 48 8b 4c 18 48 48 8b 01 41 b8 00 ?? da 00 48 8d 15 ?? ?? ?? ?? ff 50 48 44 8b c7 ba 04 00 00 00 48 3d 00 ?? da 00 44 0f 45 c2 44 89 84 24 90 00 00 00 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

