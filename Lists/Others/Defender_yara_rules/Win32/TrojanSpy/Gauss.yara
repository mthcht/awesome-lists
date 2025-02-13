rule TrojanSpy_Win32_Gauss_A_2147660321_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Gauss.plugin!A"
        threat_id = "2147660321"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Gauss"
        severity = "Critical"
        info = "plugin: plug-in component"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 fc 09 00 00 00 ff 75 f0 83 4d fc ff 8b cf e8 ?? ?? ?? ?? 81 c3 04 18 00 00 53 83 ec 1c b8 ?? ?? ?? ?? 8b f4 89 65 ec e8 ?? ?? ?? ?? c7 45 fc 0a 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 02 57 6a 05 68 00 00 00 40 50 ff 15 ?? ?? ?? ?? 8b f0 83 fe ff 75 ?? ff 15 ?? ?? ?? ?? 8b d8 83 4d fc ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Gauss_B_2147660322_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Gauss.plugin!B"
        threat_id = "2147660322"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Gauss"
        severity = "Critical"
        info = "plugin: plug-in component"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 fc 04 6a 00 6a 01 8d 75 d4 e8 ?? ?? ?? ?? 8d 45 b4 50 8b f3 e8 ?? ?? ?? ?? 8b 47 08 8d 8d 80 fd ff ff 51 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {50 6a 68 ff 15 ?? ?? ?? ?? 3b c6 0f 84 ?? ?? ?? ?? 83 f8 68 0f 87 ?? ?? ?? ?? 8d 85 f0 fe ff ff 50 89 75 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Gauss_C_2147660323_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Gauss.plugin!C"
        threat_id = "2147660323"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Gauss"
        severity = "Critical"
        info = "plugin: plug-in component"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Reliability" wide //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\WZCSVC\\Parameters\\Interfaces\\" wide //weight: 1
        $x_1_3 = "%systemroot%\\Temp\\s61cs3.dat" wide //weight: 1
        $x_1_4 = {68 80 00 00 00 68 00 00 00 40 8d 4d d4 51 8d 4d 98 e8 ?? ?? ?? ?? c6 45 fc 04 c6 45 fc 05 8d 4d 98 e8 ?? ?? ?? ?? c7 45 fc 04 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Gauss_D_2147660324_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Gauss.plugin!D"
        threat_id = "2147660324"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Gauss"
        severity = "Critical"
        info = "plugin: plug-in component"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 44 24 14 89 44 24 18 89 44 24 1c 89 44 24 20 89 44 24 24 8d 44 24 08 50 68 01 00 00 80 8d 4c 24 18 51 6a 00 c7 44 24 18 00 00 00 00 c7 44 24 20 00 00 00 00 e8 ?? ?? ?? ?? 85 c0 74 0b 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {83 78 18 08 56 57 8b f9 72 05 8b 40 04 eb 03 83 c0 04 6a 00 6a 00 6a 02 6a 00 6a 05 68 00 00 00 40 50 ff 15 ?? ?? ?? ?? 8b f0 83 fe ff 75 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Gauss_E_2147660325_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Gauss.plugin!E"
        threat_id = "2147660325"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Gauss"
        severity = "Critical"
        info = "plugin: plug-in component"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 fc 01 8d 45 d0 50 8d 4d 98 e8 ?? ?? ?? ?? 59 c6 45 fc 03 6a 01 33 db 8d 75 98 e8 ?? ?? ?? ?? 6a 08 33 c0 83 7d e8 08}  //weight: 1, accuracy: Low
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Reliability" wide //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Gauss_F_2147660326_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Gauss.plugin!F"
        threat_id = "2147660326"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Gauss"
        severity = "Critical"
        info = "plugin: plug-in component"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 03 00 00 80 ff 15 ?? ?? ?? ?? 85 c0 74 ?? c6 44 24 58 01 8d 4c 24 14 e8 ?? ?? ?? ?? c6 44 24 58 00}  //weight: 1, accuracy: Low
        $x_1_2 = "%systemroot%\\Temp\\ws1bin.dat" wide //weight: 1
        $x_1_3 = "creditlibanais" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Gauss_A_2147660327_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Gauss.A"
        threat_id = "2147660327"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Gauss"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 2c 01 00 00 8d 85 ?? ff ff ff 50 56 e8 ?? ?? 00 00 ff 75 64 81 c6 2c 01 00 00 53 56 e8 ?? ?? 00 00 83 c4 18 57 57 ff 75 6c 56 57 57 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {57 6a 0d e8 ?? ?? ?? 00 59 59 89 45 f0 c6 45 fc 05 85 c0 74 ?? 8b 4b 0c 83 60 08 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Gauss_G_2147660357_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Gauss.plugin!G"
        threat_id = "2147660357"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Gauss"
        severity = "Critical"
        info = "plugin: plug-in component"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 49 00 73 00 76 00 70 00 34 00 30 00 30 00 33 00 6c 00 74 00 72 00 45 00 76 00 65 00 6e 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {89 7d fc 50 8d 45 fc 68 86 0b 00 00 50 6a 65 57 89 7d ?? 89 7d ?? 89 7d ?? e8 07 0e 00 00 3b c7 74 0b 3d ea 00 00 00 0f 85 ?? ?? ?? ?? 6a 66 e8 ?? ?? ?? ?? 39 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Gauss_G_2147660357_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Gauss.plugin!G"
        threat_id = "2147660357"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Gauss"
        severity = "Critical"
        info = "plugin: plug-in component"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5d 08 8d 43 05 35 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 00 56 57 c7 45 fc 01 00 00 00 89 45 08 75 ?? 6a 04 5e 56}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 fc 00 28 00 00 ff 15 ?? ?? ?? ?? 8b d8 85 db 0f 84 ?? ?? ?? ?? 57 6a 70 e8 ?? ?? ?? ?? 83 65 f4 00 83 65 f8 00 8b 3d ?? ?? ?? ?? 59 83 7d f4 14}  //weight: 1, accuracy: Low
        $x_1_3 = "target.lnk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Gauss_H_2147660358_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Gauss.plugin!H"
        threat_id = "2147660358"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Gauss"
        severity = "Critical"
        info = "plugin: plug-in component"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7d 24 25 74 ?? 83 7d 24 03 0f 85 ?? ?? ?? ?? 89 75 d0 c6 45 ef 00 83 7d 24 25 8d 5e 68 74 ?? 8d 5e 5e 89 7d dc 8b 45 dc 83 f8 04}  //weight: 1, accuracy: Low
        $x_1_2 = {81 7d f0 2b 7f 39 eb 75 ?? 56 8d 45 f4 50 6a 04 8d 45 fc 50 ff 75 f8 ff d3}  //weight: 1, accuracy: Low
        $x_1_3 = "target.lnk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

