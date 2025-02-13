rule Trojan_Win64_BazzrLoader_AK_2147781312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazzrLoader.AK!MTB"
        threat_id = "2147781312"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazzrLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 33 c9 45 69 c0 ?? ?? ?? ?? b8 ?? ?? ?? ?? 41 81 c0 ?? ?? ?? ?? 41 8b c8 c1 e9 10 f7 e1 8b c1 2b c2 d1 e8 03 c2 c1 e8 0e 69 c0 ff 7f 00 00 2b c8 42 89 4c 8c ?? 49 ff c1 49 83 f9 0e 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {80 74 04 48 ?? 48 ff c0 48 83 f8 0f 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

