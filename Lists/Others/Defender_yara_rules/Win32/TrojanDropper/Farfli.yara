rule TrojanDropper_Win32_Farfli_D_2147643549_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Farfli.D"
        threat_id = "2147643549"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" ascii //weight: 1
        $x_2_2 = "36%xsvc" ascii //weight: 2
        $x_3_3 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" ascii //weight: 3
        $x_4_4 = {55 5d 90 90 41 49 90 90 90 90 41 49 90 41 49 80 3e 00}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Farfli_G_2147685393_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Farfli.G"
        threat_id = "2147685393"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 94 15 f0 fe ff ff 32 da 88 9e ?? ?? ?? 10 8b 5d f4 43 46 81 fe ?? ?? 01 00}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 db 0f b6 9c 03 00 01 00 00 30 9e ?? ?? ?? 10 bd 01 00 00 00 01 a8 04 02 00 00 83 c6 02 81 fe ?? ?? 01 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 ca 8b 55 08 03 55 c8 88 0a 8b 45 10 8b 88 04 02 00 00 83 c1 01 8b 55 10 89 8a 04 02 00 00 e9}  //weight: 1, accuracy: High
        $x_1_4 = {30 1c 2f ff 80 04 02 00 00 47 3b 7c 24 ?? [0-4] 0f 8c}  //weight: 1, accuracy: Low
        $x_1_5 = {30 0a ff 80 04 02 00 00 43 89 5d f8 3b 5d 0c 0f 8c}  //weight: 1, accuracy: High
        $x_1_6 = {0f b6 c8 8a 03 8a 14 39 88 13 88 04 39 8d 46 01 99 f7 7d 0c 43 ff 4d fc 75 c7}  //weight: 1, accuracy: High
        $x_1_7 = {5b 72 75 6e 5f 41 64 64 52 65 67 5d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 52 75 6e 22 2c 22 55 70 64 61 74 65 22 2c 2c 22 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_Win32_Farfli_J_2147722428_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Farfli.J!bit"
        threat_id = "2147722428"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 86 65 e0 00 10 34 91 88 86 80 e7 00 10 46 81 fe d8 03 00 00 72 e9}  //weight: 1, accuracy: High
        $x_1_2 = "%s\\%sex.dll" ascii //weight: 1
        $x_1_3 = "AntiVirusProduct" ascii //weight: 1
        $x_1_4 = "DQY97XGB5iZ4Vf3KsEt61HLoTOuIqJPp2AlncRCgSxUWyebhMdmzvFjNwka=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Farfli_AMTB_2147960593_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Farfli!AMTB"
        threat_id = "2147960593"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D!E&F(G*H,I-K.p5r7s9t;u=v>w?x@yAzB{D|F}H~J" ascii //weight: 1
        $x_1_2 = "get_VirtualAddress" ascii //weight: 1
        $x_1_3 = "get_TargetOffset" ascii //weight: 1
        $x_1_4 = "get_FullName" ascii //weight: 1
        $x_1_5 = "FileInfo" ascii //weight: 1
        $x_1_6 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

