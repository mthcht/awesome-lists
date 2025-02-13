rule Trojan_Win32_Mufila_DSK_2147741174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mufila.DSK!MTB"
        threat_id = "2147741174"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mufila"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {81 e3 87 8c e1 53 81 6c 24 ?? c8 ca 28 19 81 44 24 ?? 14 f5 1d 2e 35 d1 9b c8 6f 35 a9 77 64 56 81 6c 24 ?? b8 f4 e0 60 c1 e0 17 81 44 24 ?? b8 f4 e0 60 c1 e8 1e 81 6c 24 ?? 74 e0 1d 44 81 44 24 ?? 74 e0 1d 44 81 6c 24 ?? 6e 6b 98 45}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mufila_CA_2147808437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mufila.CA!MTB"
        threat_id = "2147808437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mufila"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 fc 32 04 16 88 06 83 f9 0d 72 d7}  //weight: 1, accuracy: High
        $x_1_2 = "vmcheck.dll" ascii //weight: 1
        $x_1_3 = "api_log.dll" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mufila_GJF_2147847238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mufila.GJF!MTB"
        threat_id = "2147847238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mufila"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 14 81 89 55 c8 8b 45 e0 03 45 c8 0f b6 c8 89 4d e0 8b 45 e0 8b 4d d4 8b 14 81 89 55 bc 8b 45 ec 8b 4d d4 8b 55 bc 89 14 81 8b 45 e0 8b 4d d4 8b 55 c8 89 14 81 8b 45 c8 03 45 bc 0f b6 c8 8b 55 0c 03 55 f8 0f b6 02 8b 55 d4 33 04 8a 8b 4d 0c 03 4d f8 88 01}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mufila_CREM_2147847240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mufila.CREM!MTB"
        threat_id = "2147847240"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mufila"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 c8 03 45 bc 0f b6 c8 8b 55 0c 03 55 f8 0f b6 02 8b 55 d4 33 04 8a 8b 4d 0c 03 4d f8 88 01 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

