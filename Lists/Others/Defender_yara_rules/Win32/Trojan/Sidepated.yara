rule Trojan_Win32_Sidepated_DA_2147931365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sidepated.DA!MTB"
        threat_id = "2147931365"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sidepated"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 1a 33 d2 32 87 ?? ?? ?? ?? 88 01 8d 47 01 f7 f6 0f b6 04 1a 32 87 ?? ?? ?? ?? 83 c7 04 88 41 01 8b 4c 24 0c 83 c1 04 89 4c 24 0c 81 ff 02 20 00 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

