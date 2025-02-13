rule Trojan_Win64_Cometer_DD_2147786218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cometer.DD!MTB"
        threat_id = "2147786218"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cometer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 f8 48 98 48 39 45 18 76 54 8b 45 fc 48 98 48 8b 55 28 48 83 ea 01 48 39 d0 75 07 c7 45 fc}  //weight: 10, accuracy: High
        $x_10_2 = {48 01 d0 0f b6 08 8b 45 fc 48 63 d0 48 8b 45 20 48 01 d0 0f b6 10 8b 45 f8 4c 63 c0 48 8b 45 10 4c 01 c0 31 ca 88 10}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cometer_AM_2147786448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cometer.AM!MTB"
        threat_id = "2147786448"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cometer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 89 5c 24 08 48 89 6c 24 18 48 89 74 24 20 57 41 56 41 57 48 81 ec c0 00 00 00 48 8b 05 ?? 3c 01 00 48 33 c4 48 89 84 24 b0 00 00 00 48 8d 0d ?? 1f 01 00 4c 8b ?? ff 15 eb ac 00 00 48 8b c8 48 8d 15 ?? 1f 01 00 48 8b d8 ff 15 ?? ac 00 00 48 8d 15 ?? 1f 01 00 48 8b cb 48 8b f8 ff 15 ?? ac 00 00 48 8d 15 ?? 1f 01 00 48 8b cb 48 8b f0 ff 15 ?? ac}  //weight: 10, accuracy: Low
        $x_3_2 = "LoadResource" ascii //weight: 3
        $x_3_3 = "LockResource" ascii //weight: 3
        $x_3_4 = "RtlLookupFunctionEntry" ascii //weight: 3
        $x_3_5 = "IsDebuggerPresent" ascii //weight: 3
        $x_3_6 = "IsProcessorFeaturePresent" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

