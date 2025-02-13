rule Trojan_Win32_Blorso_A_2147610474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blorso.A"
        threat_id = "2147610474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blorso"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 80 eb 01 72 0c 74 28 fe cb 74 42 fe cb 74 5c eb 76 8d 45 f8 50 e8 ?? ?? ?? ?? 8b 45 fc 83 c0 04 50 8b 45 f8 83 c0 04 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {76 70 6a 00 56 68 01 04 00 00 8d 85 ?? ?? ff ff 50 8b 45 fc 50 e8 ?? ?? ?? ?? 85 c0 74 54}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Blorso_B_2147610566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blorso.B"
        threat_id = "2147610566"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blorso"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 c7 8b 55 fc 0f b6 44 02 ff 66 89 45 fa 8d 45 f4 66 8b 55 fa 66 81 f2 ?? ?? e8 ?? ?? ?? ?? 8b 55 f4 8b c6 e8 ?? ?? ?? ?? 47 66 ff cb 75 d0}  //weight: 1, accuracy: Low
        $x_1_2 = "System64.dll" ascii //weight: 1
        $x_1_3 = {06 00 00 00 2d 4e 6f 64 33 32 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

