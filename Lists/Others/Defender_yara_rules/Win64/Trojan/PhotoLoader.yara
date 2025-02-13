rule Trojan_Win64_PhotoLoader_MKV_2147929344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PhotoLoader.MKV!MTB"
        threat_id = "2147929344"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PhotoLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 0f b6 d3 44 8d 42 01 83 e2 03 41 83 ?? 03 42 8a 44 85 ?? 02 44 95 e0 41 32 04 33 42 8b 4c 85 ?? 41 88 04 1b 83 e1 07 8b 44 95 ?? 49 ff c3 d3 c8 ff c0 89 44 95}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

