rule TrojanDropper_Win32_Sharke_C_2147601067_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sharke.C"
        threat_id = "2147601067"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sharke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fe 04 01 00 00 73 1d 32 c9 85 f6 76 17 33 c0 8a d1 80 c2 02 30 90 00 01 42 00 80 c1 01 0f b6 c1 3b c6 72 eb}  //weight: 1, accuracy: High
        $x_1_2 = {50 8d 4c 24 ?? 51 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 68 ?? ?? ?? 00 6a 00 c7 44 24 ?? 44 00 00 00 ff 15 ?? ?? ?? 00 8b [0-8] 8d 54 24 ?? 52 50 ff 15 ?? ?? ?? 00 8b 84 24 ?? ?? ?? ?? 8d 4c 24 ?? 51 8b [0-8] 6a 04 8d 54 24 1c 52 83 c0 08 50 51 ff 15 ?? ?? ?? 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? 00 50}  //weight: 1, accuracy: Low
        $x_1_3 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_4 = "ifvkck;;$o`a" ascii //weight: 1
        $x_1_5 = "wpaw55&mfg" ascii //weight: 1
        $x_1_6 = "cgrdvn;;$o`a" ascii //weight: 1
        $x_1_7 = "ujjlhb|'ng`" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Sharke_C_2147601067_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sharke.C"
        threat_id = "2147601067"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sharke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 33 c9 51 51 51 51 51 51 51 53 56 57 8b 75 10 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 b8 05 01 00 00 e8 d2 d8 ff ff 8b d8 68 04 01 00 00 53 e8 ?? ?? ?? ?? 68 04 01 00 00 53 e8 ?? ?? ?? ?? 8b c3 e8 97 d8 ff ff 8b d0 8d 45 f4 e8 65 ba ff ff c7 45 fc ff ff ff ff 8b 45 0c 50 56 6a 00 e8 ?? ?? ?? ?? 8b d8 6a 00 68 80 00 00 00 6a 02 6a 00 6a 02 68 00 00 00 40 ff 75 f4 68 ?? ?? ?? ?? 8d 45 ec 8b d6 e8 2c ba ff ff ff 75 ec 8d 45 f0 ba 03 00 00 00 e8 00 bb ff ff 8b 45 f0 e8 84 bb ff ff 50 e8 ?? ?? ?? ?? 8b f8 6a 00 8d 45 f8 50 53 6a 00 e8 ?? ?? ?? ?? 50 53 6a 00 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 50 57 e8 ?? ?? ?? ?? 57 e8 ?? ?? ?? ?? 6a 01 6a 00 6a 00 ff 75 f4 68}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 48 65 6c 70 5c 00 00 4f 50 45 4e}  //weight: 1, accuracy: High
        $x_1_3 = "FindResourceA" ascii //weight: 1
        $x_1_4 = "EnumResourceNamesA" ascii //weight: 1
        $x_1_5 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Sharke_B_2147605044_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sharke.B"
        threat_id = "2147605044"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sharke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 57 8b 7c 24 0c 57 ff 15 ?? ?? ?? 00 57 68 e8 00 41 00 8b f0 ff 15 ?? ?? ?? 00 81 fe 04 01 00 00 73 22 32 c9 85 f6 76 1c 33 c0 eb 03 8d 49 00 8a d1 80 c2 02 30 90 e8 00 41 00 80 c1 01 0f b6 c1 3b c6 72 eb 5f b8 e8 00 41 00 5e c3}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 8b f0 68 05 42 02 00 56 e8 ?? ?? ?? 00 56 6a 01 8d 84 24 64 03 00 00 6a 26 50 e8 ?? ?? ?? 00 56 e8 ?? ?? ?? 00 83 c4 28}  //weight: 1, accuracy: Low
        $x_1_3 = "ifvkck;;$o`a" ascii //weight: 1
        $x_1_4 = "wpaw55&mfg" ascii //weight: 1
        $x_1_5 = "cgrdvn;;$o`a" ascii //weight: 1
        $x_1_6 = "ujjlhb|'ng`" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

