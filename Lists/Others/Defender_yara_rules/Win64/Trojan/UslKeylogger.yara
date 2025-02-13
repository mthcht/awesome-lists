rule Trojan_Win64_UslKeylogger_A_2147894252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/UslKeylogger.A!MTB"
        threat_id = "2147894252"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "UslKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 64 ff c0 89 45 64 81 7d 64 be 00 00 00 7f ?? 8b 4d 64 ff 15 ?? ?? ?? ?? 98 3d 01 80 ff ff 75 ?? 0f b6 4d 64 e8 7d}  //weight: 2, accuracy: Low
        $x_2_2 = {48 63 85 d4 00 00 00 48 8d 0d 83 e5 fe ff 0f b6 84 01 74 1c 01 00 8b 84 81 34 1c 01 00 48 03 c1 ff ?? 4c 8d 05 ?? ?? 00 00 48 8d 15 ?? ?? 00 00 48 8b 4d 08 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

