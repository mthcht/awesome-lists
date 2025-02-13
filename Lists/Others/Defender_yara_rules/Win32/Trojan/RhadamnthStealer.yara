rule Trojan_Win32_RhadamnthStealer_PA_2147839495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RhadamnthStealer.PA!MTB"
        threat_id = "2147839495"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RhadamnthStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2c 01 88 45 ?? 8b 45 ?? 33 85 [0-4] 0f b6 4d ?? 8b 95 [0-4] 89 04 8a e9}  //weight: 1, accuracy: Low
        $x_1_2 = {2c 01 88 45 ?? 8b 45 ?? 8b 8d [0-4] d3 e0 0f b6 4d ?? 8b 95 [0-4] 89 04 8a e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

