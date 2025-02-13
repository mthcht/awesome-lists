rule Trojan_Win32_VirRansom_DM_2147786458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VirRansom.DM!MTB"
        threat_id = "2147786458"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VirRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {99 b9 03 00 00 00 f7 f9 8b 45 e8 0f be 0c 10 8b 95 ?? fd ff ff 0f b6 44 15 f4 33 c1 8b 8d ?? fd ff ff 88 44 0d f4 eb ba}  //weight: 10, accuracy: Low
        $x_10_2 = {0f b6 55 ef 0f b6 45 f7 3b d0 75 0c 0f b6 4d f0 0f b6 55 f8 3b ca 74 0e 8b 45 fc 83 c0 01 89 45 fc}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

