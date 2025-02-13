rule Trojan_Win32_Dyloader_A_2147718592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dyloader.A!bit"
        threat_id = "2147718592"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dyloader"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 30 88 0c 38 88 1c 30 8b 75 0c 02 1c 38 8a 0c 16 0f b6 db 32 0c 18 8b 5d 10 88 0c 13 42 eb}  //weight: 1, accuracy: High
        $x_1_2 = {66 8b 0c 46 8d 95 ?? ?? ff ff 83 f1 08 88 8c 05 ?? ?? ff ff 40 83 f8 08 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dyloader_B_2147728121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dyloader.B!bit"
        threat_id = "2147728121"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dyloader"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 fc 83 c2 01 89 55 fc 8b 45 fc 3b 45 0c 73 32 8b 4d 08 8a 11 32 55 f8 8b 45 08 88 10 8b 4d 08 8a 11 02 55 f8 8b 45 08 88 10 8b 4d 08 8a 11 32 55 f8 8b 45 08 88 10 8b 4d 08 83 c1 01 89 4d 08 eb bd}  //weight: 1, accuracy: High
        $x_1_2 = {50 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 8b 4d 08 51 6a 00 ff 15 ?? ?? ?? 10 3b f4 e8 ?? ?? ?? 00 89 45}  //weight: 1, accuracy: Low
        $x_1_3 = {83 7d fc 00 0f 84 9b 00 00 00 8b 8d ?? ?? ?? ff 51 8b 55 f8 52 e8 ?? ?? ?? ff 83 c4 08 85 c0 74 28 8b f4 6a 40 68 00 30 00 00 8b 45 18 50 8b 4d 0c 8b 51 34 52 8b 45 f8 50 ff 55 fc 3b f4 e8 ?? ?? ?? 00 89 85 ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

