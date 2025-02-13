rule Trojan_Win64_Ligooc_GHS_2147845578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ligooc.GHS!MTB"
        threat_id = "2147845578"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ligooc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f af c1 48 63 4f 3c 89 87 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 44 88 0c 01 ff 47 3c 8b 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 05 ?? ?? ?? ?? 2b 8f ?? ?? ?? ?? 03 c8 89 0d ?? ?? ?? ?? 8b 47 7c 35 e8 d1 04 00 29 87 ?? ?? ?? ?? b8 ?? ?? ?? ?? 2b 47 5c 01 07 49 81 fa 20 6d 00 00 0f 8c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

