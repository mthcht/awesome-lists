rule Trojan_Win32_Sality_R_2147600458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sality.R"
        threat_id = "2147600458"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sality"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 6f 68 de 00 00 00 6a 00 ff 15 ?? ?? 40 00 a3 ?? ?? 40 00 83 3d ?? ?? 40 00 00 0f 84 9d 02 00 00 8b 0d ?? ?? 40 00 51 6a 00 ff 15 ?? ?? 40 00 a3 ?? ?? 40 00 8b 15 ?? ?? 40 00 52 6a 00 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 6f 68 4d 01 00 00 6a 00 ff 15 ?? ?? 40 00 a3 ?? ?? 40 00 83 3d ?? ?? 40 00 00 0f 84 a3 02 00 00 8b 15 ?? ?? 40 00 52 6a 00 ff 15 ?? ?? 40 00 a3 ?? ?? 40 00 a1 ?? ?? 40 00 50 6a 00 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_3 = "\\%x.exe" ascii //weight: 1
        $x_1_4 = "\\%d.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Sality_PADQ_2147907483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sality.PADQ!MTB"
        threat_id = "2147907483"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sality"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 f2 ea 19 a1 ed ff c6 0f bf c6 2a ef 88 d8 00 fd 3a ea 69 cc 54 2d da 18 fe c2 8d 05 cf f9 ff ff 85 c9 c6 c6 3f c6 c5 e4 2d 23 08 00 00 74 09}  //weight: 1, accuracy: High
        $x_1_2 = {f3 f7 c1 6b f5 14 5a 8a f7 03 e0 81 ff f4 b1 00 00 74 02 23 f0 81 ec ab f1 ff ff 8a d6 c7 c3 ba a0 75 d2 0c 96 84 ee 84 c0 0f af cf 42 81 fb 35 04 00 00 0f 82 85 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

