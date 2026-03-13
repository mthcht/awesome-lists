rule Trojan_Win64_QatarRAT_ABQR_2147964668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/QatarRAT.ABQR!MTB"
        threat_id = "2147964668"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "QatarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 04 24 ff c0 89 04 24 48 63 04 24 48 83 f8 ?? ?? ?? 48 63 04 24 48 8b 4c 24 ?? 0f be 04 01 8b 0c 24 83 e9 ?? 0f be c9 33 c1 48 63 0c 24 48 8b 54 24 ?? 88 04 0a eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

