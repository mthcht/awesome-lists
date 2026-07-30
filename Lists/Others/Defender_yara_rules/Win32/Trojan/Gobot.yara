rule Trojan_Win32_Gobot_AGO_2147974840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gobot.AGO!MTB"
        threat_id = "2147974840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gobot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 1c 1c 60 30 e8 ?? ?? ?? ?? a3 e4 3c 41 00 b8 45 bb 58 e0 e8 ?? ?? ?? ?? a3 e8 3c 41 00 b8 16 d9 51 a8 e8 ?? ?? ?? ?? a3 ec 3c 41 00 b8 02 91 d8 59 e8 ?? ?? ?? ?? a3 f0 3c 41 00 b8 fd 53 ca 1c}  //weight: 2, accuracy: Low
        $x_1_2 = {99 03 04 24 13 54 24 04 83 c4 08 66 8b 00 66 25 ff ff 0f b7 c0 c1 e0 02 03 46 1c 33 d2 52 50 a1 ?? ?? ?? ?? 99 03 04 24 13 54 24 04 83 c4 08 8b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

