rule Trojan_Win32_ZCrypren_A_2147756839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZCrypren.A!MTB"
        threat_id = "2147756839"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZCrypren"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 84 24 7c 08 00 00 99 6a 0c 59 f7 f9 8b 4c 24 20 0f b6 c9 03 c1 b9 ?? ?? ?? ?? 2b 44 24 1c 0f b6 c9 03 4c 24 0c 03 c1 89 44 24 0c 33 ff 8b 4c 24 20 8b 74 24 10 0f b7 c1 03 c6 74 2c 33 d2 c7 44 24 3c 0f 00 00 00 8b c6 f7 74 24 3c 8d 94 24 7c 08 00 00 2b c8 0f b7 c2 2b c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

