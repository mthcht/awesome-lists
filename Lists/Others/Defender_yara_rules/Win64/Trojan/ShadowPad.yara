rule Trojan_Win64_ShadowPad_ABK_2147957042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShadowPad.ABK!MTB"
        threat_id = "2147957042"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShadowPad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b 54 24 38 48 8d 44 24 60 48 03 54 24 20 48 3b c2 73 1b 48 8b 03 48 3b c7 75 0a 48 8d 05 ?? ?? ?? ?? 48 89 03 48 83 c3 08 48 3b da 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

