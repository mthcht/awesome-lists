rule Trojan_Win32_HyperBro_GXZ_2147910976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HyperBro.GXZ!MTB"
        threat_id = "2147910976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HyperBro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 f4 83 c0 01 89 45 f4 8b 4d f4 3b 4d f8 ?? ?? 8b 55 ec 03 55 f4 0f b6 02 33 45 e4 8b 4d ec 03 4d f4 88 01 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

