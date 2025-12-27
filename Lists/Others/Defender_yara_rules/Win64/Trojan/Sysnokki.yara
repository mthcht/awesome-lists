rule Trojan_Win64_Sysnokki_GTD_2147958250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sysnokki.GTD!MTB"
        threat_id = "2147958250"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sysnokki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {45 8b f4 c7 44 24 20 40 00 00 00 41 b9 00 30 00 00 45 8b c4 33 d2 48 8b ce ff 15 ?? ?? ?? ?? 4c 8b e0 48 85 c0 74 6a 48 89 7c 24 20 45 8b ce 4c 8b c3 48 8b d0 48 8b ce ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

