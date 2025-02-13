rule Rogue_Win32_FakeVimes_141340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeVimes"
        threat_id = "141340"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeVimes"
        severity = "177"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "httpreportcountdomnet" ascii //weight: 2
        $x_1_2 = "VirusDoctorInstallerMutex" ascii //weight: 1
        $x_1_3 = "AdwareProjects\\DeskTopWork\\Cleaners\\VirusDoctor" ascii //weight: 1
        $x_1_4 = "opentaskkillexe" ascii //weight: 1
        $x_1_5 = "antitrojanexeantivirusexeantsexeapimonitorexeaplicaexeapvxdwinexe" ascii //weight: 1
        $x_1_6 = "SMART_INTERNET_PROTECTION__UNINSTALLSmartIPexeSMART_INTERNET_PROTECTION__APP" ascii //weight: 1
        $x_1_7 = "ifexistsgotoRepeatdelsRepeatdelbat" ascii //weight: 1
        $x_1_8 = "get_install_filephpindexphp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeVimes_141340_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeVimes"
        threat_id = "141340"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeVimes"
        severity = "177"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mid=%s&wv=%s" ascii //weight: 1
        $x_1_2 = "UserID=%s&wv=%s" ascii //weight: 1
        $x_1_3 = "iexpl* /IM" ascii //weight: 1
        $x_1_4 = "hosts.o1d" ascii //weight: 1
        $x_1_5 = "Virus Doctor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_FakeVimes_141340_2
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeVimes"
        threat_id = "141340"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeVimes"
        severity = "177"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TFakeSearchVirus" ascii //weight: 1
        $x_1_2 = "FakeSearchVirusDefenderUnit" ascii //weight: 1
        $x_1_3 = "l_Logo_Defender" ascii //weight: 1
        $x_1_4 = "INFECTED_NAG" ascii //weight: 1
        $x_1_5 = "SPAM_NAG" ascii //weight: 1
        $x_1_6 = "UPDATE_ALERT_NAG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_FakeVimes_141340_3
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeVimes"
        threat_id = "141340"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeVimes"
        severity = "177"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mid=%s&wv=%s" ascii //weight: 1
        $x_1_2 = "servn.exe;winssk32.exe;winstart.exe;winstart001.exe;wintsk32.exe;" ascii //weight: 1
        $x_2_3 = {56 69 72 75 73 44 6f 63 74 6f 72 49 6e 73 74 61 6c 6c 65 72 4d 75 74 65 78 00}  //weight: 2, accuracy: High
        $x_2_4 = "D:\\Work\\AdwareProjects\\DeskTopWork\\Cleaners\\VirusDoctor" ascii //weight: 2
        $x_1_5 = "\\SysFld\\fastav.cfg" ascii //weight: 1
        $x_1_6 = {2f 72 65 70 6f 72 74 73 2f 6d 69 6e 73 74 61 6c 6c 73 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_7 = {72 65 70 6f 72 74 73 2f 67 65 74 5f 69 6e 73 74 61 6c 6c 5f 66 69 6c 65 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_2_8 = "controller=microinstaller&abbr=%s" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeVimes_141340_4
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeVimes"
        threat_id = "141340"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeVimes"
        severity = "177"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $n_100_1 = "O-Key Dongle|OBT" ascii //weight: -100
        $x_2_2 = {8b 47 3c 03 c7 89 45 ?? 6a 04 68 00 30 00 00 8b 45 00 8b 40 50 50 8b 45 00 e8}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 40 3c 03 45 ?? 89 45 ?? 6a 01 68 00 20 00 00 8b 45 01 8b 40 50 50 53 e8}  //weight: 2, accuracy: Low
        $x_2_4 = {6a 40 68 00 30 00 00 [0-9] 8b ?? 50 50 [0-9] 8b ?? 34 50 8b 45 ?? 50 03 02 01 08 ff 15 e8 a1 ?? ?? ?? ?? 8b 00 ff d0}  //weight: 2, accuracy: Low
        $x_2_5 = {6a 40 68 00 30 00 00 51 52 50 ff 15 ?? ?? ?? ?? c3 06 00 [0-5] (c2|c3)}  //weight: 2, accuracy: Low
        $x_2_6 = {0f b7 40 06 48 85 c0 (72|7c) ?? 40 89 45 ?? 33 db 8d (45 ?? 50 8d 34 9b 8b 45 ??|04 9b 8b 7c c6 08 8d) 8b 44 (f0|c6) 10}  //weight: 2, accuracy: Low
        $x_2_7 = {32 c1 8b 4d f8 8b 7d ?? 0f b6 4c 39 ff 03 c9 c1 e9 02 32 c1 32 d0 88 55 ef}  //weight: 2, accuracy: Low
        $x_1_8 = {8b 40 28 03 45 03 00 8b 45 ?? ?? ?? ?? ?? ?? ?? (a3|89)}  //weight: 1, accuracy: Low
        $x_1_9 = "^WriteProcessMemory^VirtualAllocEx^VirtualProtectEx^ZwUnmapViewOfSection^ReadProc" ascii //weight: 1
        $x_1_10 = {85 c9 74 19 8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41 41 eb 03 83 c1 05 01 c1}  //weight: 1, accuracy: High
        $x_2_11 = {8b 47 28 03 45 ?? 8b 55 ?? 89 82 b0 00 00 00 8b 45 ?? 50 8b 45 ?? 50 (e8|a1 ?? ?? ?? ?? 8b 00)}  //weight: 2, accuracy: Low
        $x_2_12 = {8b 47 28 03 45 ?? 89 83 b0 00 00 00}  //weight: 2, accuracy: Low
        $x_2_13 = {03 43 28 89 86 b0 00 00 00}  //weight: 2, accuracy: High
        $x_2_14 = {89 87 b0 00 00 00 06 00 (8b ?? ?? 03 ??|8b ??)}  //weight: 2, accuracy: Low
        $x_2_15 = {89 b0 b0 00 00 00 18 00 [0-15] 8b 45 [0-16] 03 47 28 [0-15] 8b 45}  //weight: 2, accuracy: Low
        $x_1_16 = {07 00 01 00 02 00 c7}  //weight: 1, accuracy: Low
        $x_1_17 = {06 48 66 85 c0 (72 ??|0f 82 ?? ?? ?? ??) 40 66 89 08 00 66 8b}  //weight: 1, accuracy: Low
        $x_1_18 = {8b 40 3c 8b ?? 03 c2 05 f8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_19 = {8b 40 3c 03 c3 05 f8 00 00 00}  //weight: 1, accuracy: High
        $x_1_20 = {66 8b 7b 06 4f 66 85 ff 72 ?? 47 33}  //weight: 1, accuracy: Low
        $x_1_21 = {8b 58 3c 03 de 81 c3 f8 00 00 00}  //weight: 1, accuracy: High
        $x_1_22 = {68 f8 00 00 00 56 8b 45 ?? 8b 40 3c 03 ?? 50}  //weight: 1, accuracy: Low
        $x_1_23 = {68 f8 00 00 00 8b 45 ?? 50 8b c3 03 46 3c 50}  //weight: 1, accuracy: Low
        $x_1_24 = {d1 e0 03 42 24 03 45 0c 66 8b 00 [0-32] 25 ff ff 00 00 c1 e0 02 03 42 1c [0-9] 03 45 0c [0-9] 8b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

