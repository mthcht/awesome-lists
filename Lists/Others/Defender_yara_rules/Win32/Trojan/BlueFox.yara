rule Trojan_Win32_BlueFox_RPK_2147834787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlueFox.RPK!MTB"
        threat_id = "2147834787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlueFox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f4 83 c1 01 89 4d f4 8b 55 f4 3b 55 0c 73 2c 8b 45 08 03 45 f4 0f b6 08 8b 55 f4 81 e2 ?? ?? ?? ?? 79 05 4a 83 ca f0 42 8b 45 fc 0f b6 14 10 33 ca 8b 45 f8 03 45 f4 88 08 eb c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

