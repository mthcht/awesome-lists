rule Trojan_Win32_RaStealer_PAA_2147837634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RaStealer.PAA!MTB"
        threat_id = "2147837634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 0c 8b 45 f4 01 45 0c 8b c6 c1 e0 04 03 45 f0 8d 0c 33 33 c1 33 45 0c 81 c3 ?? ?? ?? ?? 2b f8 ff 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RaStealer_PAB_2147839274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RaStealer.PAB!MTB"
        threat_id = "2147839274"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8b 4d c8 89 45 fc 8d 45 fc e8 ?? ?? ?? ?? 8b 45 fc 33 45 f0 89 1d ?? ?? ?? ?? 31 45 f8 8b 45 f8 29 45 f4 81 45 e0 ?? ?? ?? ?? ff 4d dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RaStealer_PAC_2147839429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RaStealer.PAC!MTB"
        threat_id = "2147839429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 8b 4d ?? fe c3 8b 09 03 ca 0f b6 d3 8d 14 96 89 55 ec 47 83 45 0c ?? 89 0a eb b3 23 4d f0 8b 55 f8 8b 0c 11}  //weight: 1, accuracy: Low
        $x_1_2 = {fe c3 8b c1 0f b6 cb 8d 14 8e 8b 4d 0c 89 55 ec 8b 09 eb ?? 8b 55 f4 8b c1 8b 4d 0c fe c3 8b 09 03 ca 0f b6 d3 8d 14 96 89 55 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

