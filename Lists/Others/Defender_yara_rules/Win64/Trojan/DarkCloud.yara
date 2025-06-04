rule Trojan_Win64_DarkCloud_DB_2147942806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DarkCloud.DB!MTB"
        threat_id = "2147942806"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 01 43 0f b6 0c 01 01 c1 0f b6 c1 48 8b 4d b0 8a 04 01 48 63 4d f4 41 30 04 0a 8b 45 f4 83 c0 01 89 45 e0 8b 05 ?? ?? ?? ?? 8d 48 ff 0f af c8 f6 c1 01 b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

