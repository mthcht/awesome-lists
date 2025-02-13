rule Trojan_Win32_Grandsteal_RPY_2147844310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grandsteal.RPY!MTB"
        threat_id = "2147844310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandsteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 0e b8 03 00 00 00 0f b6 0d ?? ?? ?? ?? 30 4e 01 0f b6 0d ?? ?? ?? ?? 30 4e 02 0f b6 0d ?? ?? ?? ?? 30 4e 03 40 83 f8 05 74 09 8a 0d ?? ?? ?? ?? 30 0c 30 83 f8 07 75 ec a0 ?? ?? ?? ?? 02 c0 30 46 05 5e c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

