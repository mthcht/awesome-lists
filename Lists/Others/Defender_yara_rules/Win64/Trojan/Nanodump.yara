rule Trojan_Win64_Nanodump_ANO_2147940032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Nanodump.ANO!MTB"
        threat_id = "2147940032"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Nanodump"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 45 a0 48 8b 45 a0 48 83 c0 05 48 89 45 98 48 8b 45 98 48 89 c1 e8 ?? ?? ?? ?? 48 89 45 e8 48 8b 4d b0 48 8b 55 98 48 8b 45 e8 49 89 c8 48 89 c1 48 8b 05 ?? ?? 00 00 ff d0 48 8b 55 98 48 8b 45 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

