rule Trojan_Win32_APosT_SIB_2147787694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/APosT.SIB!MTB"
        threat_id = "2147787694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "APosT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 08 03 95 ?? ?? ?? ?? 0f b6 02 33 c1 8b 4d 08 03 8d 00 88 01 8b 85 00 83 c0 ?? 89 85 00 8b 8d 00 3b 4d 0c 0f 83 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 83 c2 ?? 89 95 08 8b 85 08 33 d2 b9 ?? ?? ?? ?? f7 f1 89 95 08 8b 95 08 0f b6 84 15 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 33 d2 b9 ?? ?? ?? ?? f7 f1 89 95 10 8b 95 10 8a 84 15 0f 88 85 ?? ?? ?? ?? 8b 8d 10 8b 95 08 8a 84 15 0f 88 84 0d 0f 8b 8d 08 8a 95 15 88 94 0d 0f 8b 85 08 0f b6 8c 05 0f 8b 95 10 0f b6 84 15 0f 03 c8 81 e1 ?? ?? ?? ?? 79 ?? 49 81 c9 ?? ?? ?? ?? 41 0f b6 8c 0d 0f 8b 55 08}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 f7 75 14 0f be 84 15 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 0f b6 8c 15 ?? ?? ?? ?? 03 c1 33 d2 b9 ?? ?? ?? ?? f7 f1 89 95 01 8b 95 01 0f b6 84 15 03 8b 8d 02 0f b6 94 0d 03 33 d0 89 95 ?? ?? ?? ?? 8b 85 02 8a 8d 0a 88 8c 05 03 0f b6 95 0a 8b 85 01 0f b6 8c 05 03 33 ca 89 8d ?? ?? ?? ?? 8b 95 01 8a 85 11 88 84 15 03 0f b6 8d 11 8b 95 02 0f b6 84 15 03 33 c1 8b 8d 02 88 84 0d 03 8b 8d 02 83 c1 ?? 89 8d 02 81 bd 02 ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? 8b 85 02 33 d2 f7 75 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

