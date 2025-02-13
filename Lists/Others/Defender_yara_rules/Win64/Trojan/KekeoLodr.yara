rule Trojan_Win64_KekeoLodr_MK_2147839504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KekeoLodr.MK!MTB"
        threat_id = "2147839504"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KekeoLodr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 f0 44 89 f1 48 83 c7 ?? 48 d3 f8 41 30 44 1c ?? 49 39 fd 75 ?? 48 ff c6 48 83 c3 ?? 71}  //weight: 1, accuracy: Low
        $x_1_2 = {48 ff c3 42 88 54 37 10 83 e3 0f 49 ff c6 e9 22 00 48 8d 0d ?? ?? ?? ?? 42 8a 54 35 ?? 32 94 19}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

