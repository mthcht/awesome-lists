rule Trojan_Win32_Fakeantispypro_2147624346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fakeantispypro"
        threat_id = "2147624346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakeantispypro"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 02 46 46 66 83 3e 20 74 f8 0f b7 06 83 f8 61 74 37 83 f8 72 74 2b 83 f8 77 74 1f}  //weight: 1, accuracy: High
        $x_1_2 = {eb 01 46 80 3e 20 74 fa 8a 06 3c 61 74 39 3c 72 74 2c 3c 77 74 1f}  //weight: 1, accuracy: High
        $x_1_3 = "SOFTWARE\\AntiSpyware Pro\\SBlocker" wide //weight: 1
        $x_1_4 = "AntiSpyware Pro Site Blocker Button" wide //weight: 1
        $x_1_5 = "aspropurch.exe" wide //weight: 1
        $x_1_6 = "ASProSB.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Fakeantispypro_2147624346_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fakeantispypro"
        threat_id = "2147624346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakeantispypro"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 45 66 81 78 18 0b 01 75 3d b8 00 00 00 10 2b c8 51 e8 83 ff ff ff 59 85 c0 74 2b 8b 40 24 c1 e8 1f f7 d0 83 e0 01 c7 45 fc fe ff ff ff eb 20 8b 45 ec 8b 00 8b 00 33 c9 3d 05 00 00 c0}  //weight: 1, accuracy: High
        $x_1_2 = "BlankActiveXCtrl" ascii //weight: 1
        $x_1_3 = "BlankActiveXPropPage" ascii //weight: 1
        $x_1_4 = "\\desktop\\trunk\\utils\\blankactivex\\release\\BlankActiveX" ascii //weight: 1
        $x_1_5 = {42 6c 61 6e 6b 41 63 74 69 76 65 58 2e 4f 43 58 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Fakeantispypro_2147624346_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fakeantispypro"
        threat_id = "2147624346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakeantispypro"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 bc 24 50 10 00 00 30 75 02 33 db 8d bc 24 52 10 00 00 57 e8 ?? ?? 00 00 83 c4 04 66 83 7c 24 4a 00 8b f8 75 54}  //weight: 1, accuracy: Low
        $x_1_2 = {83 fd e0 0f 87 ?? ?? 00 00 53 8b 1d ?? ?? 00 10 56 57 33 f6 39 35 ?? ?? 00 10 8b fd 75 18 e8 ?? ?? 00 00 6a 1e e8 ?? ?? 00 00 68 ff 00 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = "SOFTWARE\\AntiSpyware Pro\\WindowController" wide //weight: 1
        $x_1_4 = "ASpyProPUBlk.dll" wide //weight: 1
        $x_1_5 = "AntiSpyware Pro-WindowController" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

