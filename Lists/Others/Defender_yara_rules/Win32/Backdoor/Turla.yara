rule Backdoor_Win32_Turla_S_2147690040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Turla.S"
        threat_id = "2147690040"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Turla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Administrator\\Application Data\\Microsoft\\Windows\\PrivacIE\\High\\desktop.ini" ascii //weight: 1
        $x_1_2 = "\\Administrator\\Application Data\\Microsoft\\Windows\\PrivacIE\\High\\index.dat" ascii //weight: 1
        $x_1_3 = "97ryuhf023" wide //weight: 1
        $x_1_4 = "cryptsp.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Turla_A_2147691959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Turla.A!dha"
        threat_id = "2147691959"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Turla"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "STOP|KILL|" ascii //weight: 1
        $x_1_2 = "OPER|Sniffer" ascii //weight: 1
        $x_1_3 = "%02d/%02d/%02d|%02d:%02d:%02d|%s|s|" ascii //weight: 1
        $x_1_4 = "no_server_hijack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Turla_G_2147691960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Turla.G!dha"
        threat_id = "2147691960"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Turla"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 4c 3d f0 40 83 f8 01 72 02}  //weight: 1, accuracy: High
        $x_1_2 = {30 01 46 3b 74 24 10 72 db}  //weight: 1, accuracy: High
        $x_1_3 = {74 1c ff 36 ff 75 e8 53 53 68 2c 20 22 00 57 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Turla_H_2147691966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Turla.H!dha"
        threat_id = "2147691966"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Turla"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 4c 05 98 40 83 f8 0c 72 f6}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 b8 2e 64 6f 63 88 5d bc c7 45 d8 2e 70 64 66}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Turla_I_2147691967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Turla.I!dha"
        threat_id = "2147691967"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Turla"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 74 04 10 55 40 83 f8 0c 72 f5}  //weight: 1, accuracy: High
        $x_1_2 = "isp=%d cp=%S dbp=%S hmod=0x%08X" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Turla_K_2147691969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Turla.K!dha"
        threat_id = "2147691969"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Turla"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f be 02 83 f0 55 8b 4d 08 03 4d fc 88 01 eb d9}  //weight: 1, accuracy: High
        $x_1_2 = "+[%d/24h] %02d.%02d.%04d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Turla_B_2147691971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Turla.B!dha"
        threat_id = "2147691971"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Turla"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 76 8b c5 8d 50 01 8a 08 83 c0 01 3a cb 75 f7 2b c2 8d 54 24 20 52 83 c0 01 50 55 57 56 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {8b 04 24 8b 4c 24 08 83 e9 04 0f 84 ?? ?? ?? ?? 83 e9 01 74 5a 83 e9 01 75 c3 8b 4c 24 0c 83 e9 00 74 36 83 e9 01 74 1b 83 e9 01 75 b0 f7 d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Turla_V_2147697645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Turla.V!dha"
        threat_id = "2147697645"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Turla"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 63 6f 6e 66 69 67 5f 72 65 61 64 5f 75 69 6e 74 33 32}  //weight: 1, accuracy: High
        $x_1_2 = {00 63 6f 64 65 5f 72 65 73 75 6c 74 5f 74 62 6c}  //weight: 1, accuracy: High
        $x_1_3 = {00 6d 32 62 5f 72 61 77}  //weight: 1, accuracy: High
        $x_1_4 = {00 71 6d 5f 72 6d 5f 6c 69 73 74}  //weight: 1, accuracy: High
        $x_1_5 = {00 72 6b 5f 70 63 61 70 5f 63 6d 64}  //weight: 1, accuracy: High
        $x_1_6 = {00 72 65 61 64 5f 70 65 65 72 5f 6e 66 6f}  //weight: 1, accuracy: High
        $x_1_7 = {00 73 6e 61 6b 65 5f 61 6c 6c 6f 63}  //weight: 1, accuracy: High
        $x_1_8 = {00 73 6e 61 6b 65 5f 66 72 65 65}  //weight: 1, accuracy: High
        $x_1_9 = {00 73 6e 61 6b 65 5f 6d 6f 64 75 6c 65 73 5f 63 6f 6d 6d 61 6e 64}  //weight: 1, accuracy: High
        $x_1_10 = {00 74 5f 73 65 74 6f 70 74 62 69 6e}  //weight: 1, accuracy: High
        $x_1_11 = {00 74 5f 73 65 74 6f 70 74 6c 69 73 74}  //weight: 1, accuracy: High
        $x_1_12 = {00 74 63 5f 63 61 6e 63 65 6c}  //weight: 1, accuracy: High
        $x_1_13 = {00 74 63 5f 66 72 65 65 5f 64 61 74 61}  //weight: 1, accuracy: High
        $x_1_14 = {00 74 63 5f 67 65 74 5f 72 65 70 6c 79}  //weight: 1, accuracy: High
        $x_1_15 = {00 74 63 5f 72 65 61 64 5f 72 65 71 75 65 73 74 5f 70 69 70 65}  //weight: 1, accuracy: High
        $x_1_16 = {00 74 63 5f 73 65 6e 64 5f 72 65 71 75 65 73 74 5f 62 75 66 73}  //weight: 1, accuracy: High
        $x_1_17 = {00 74 63 5f 73 6f 63 6b 65 74}  //weight: 1, accuracy: High
        $x_1_18 = {00 74 72 5f 61 6c 6c 6f 63}  //weight: 1, accuracy: High
        $x_1_19 = {00 74 72 5f 67 65 74 5f 63 61 6c 6c 62 61 63 6b 73}  //weight: 1, accuracy: High
        $x_1_20 = {00 74 72 5f 77 72 69 74 65 5f 70 69 70 65}  //weight: 1, accuracy: High
        $x_1_21 = {00 77 72 69 74 65 5f 70 65 65 72 5f 6e 66 6f}  //weight: 1, accuracy: High
        $x_1_22 = {00 69 6e 6a 5f 73 6e 61 6b 65 5f}  //weight: 1, accuracy: High
        $x_1_23 = {00 72 6b 63 74 6c 5f}  //weight: 1, accuracy: High
        $x_1_24 = {00 69 6e 6a 5f 73 65 72 76 69 63 65 73 5f}  //weight: 1, accuracy: High
        $x_2_25 = {2e 64 6c 6c 00 4d 6f 64 75 6c 65 43 6f 6d 6d 61 6e 64 00 4d 6f 64 75 6c 65 53 74 61 72 74 00 4d 6f 64 75 6c 65 53 74 6f 70 00}  //weight: 2, accuracy: High
        $x_1_26 = "no_server_hijack" ascii //weight: 1
        $x_1_27 = "reliable_n_tries" ascii //weight: 1
        $x_1_28 = "frag_no_scrambling" ascii //weight: 1
        $x_1_29 = "rcv_buf=%d%c" ascii //weight: 1
        $x_1_30 = {00 74 61 69 63 68 69 6e}  //weight: 1, accuracy: High
        $x_1_31 = {00 77 69 6e 69 6e 65 74 5f 61 63 74 69 76 61 74 65}  //weight: 1, accuracy: High
        $x_2_32 = {09 74 69 3d 25 75 09 73 74 3d 25 64 09 73 6f 3d 25 78 09}  //weight: 2, accuracy: High
        $x_2_33 = "=query&id=%u:%u:%u:%u&serv=%s&lang=en&q=%u-%u&date=%s" ascii //weight: 2
        $x_1_34 = "ST|Carbon v" ascii //weight: 1
        $x_1_35 = "OPER|Wrong" ascii //weight: 1
        $x_1_36 = "OPER|Sniffer" ascii //weight: 1
        $x_1_37 = "mstok %s" ascii //weight: 1
        $x_1_38 = "##mst %s %d" ascii //weight: 1
        $x_1_39 = "%s#%s.exe#%s##Y" ascii //weight: 1
        $x_1_40 = "##issm prs!" ascii //weight: 1
        $x_1_41 = "##dk %S 0x%08x" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Turla_X_2147723278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Turla.X!dha"
        threat_id = "2147723278"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Turla"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 d1 83 e1 08 81 e3 f7 1f 00 00 33 d9 8b cb c1 f9 0a d1 f8 83 e1 07}  //weight: 1, accuracy: High
        $x_1_2 = {f7 d1 41 81 e4 f7 1f 00 00 83 e1 08 44 33 e1 41 8b cc c1 f9 0a 83 e1 07}  //weight: 1, accuracy: High
        $x_1_3 = "KernelInjector::CopyDllFromBuffer" wide //weight: 1
        $x_1_4 = "KernelInjector::KernelInjector" wide //weight: 1
        $x_1_5 = "{531511FA-190D-5D85-8A4A-279F2F592CC7}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Turla_Y_2147723279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Turla.Y!dha"
        threat_id = "2147723279"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Turla"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\\\.\\pipe\\Winsock2\\CatalogChangeListener-FFFF-F" wide //weight: 2
        $x_1_2 = {2e 00 74 00 6d 00 70 00 2e 00 63 00 76 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "%TEMP%\\KB943729.log" wide //weight: 1
        $x_1_4 = "%0024\\explorer.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Turla_AA_2147731975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Turla.AA"
        threat_id = "2147731975"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Turla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 83 ec 48 4c 8d 0d c1 ef ff ff 31 d2 31 c9 4c 8d 05 b6 f3 ff ff 48 8d 44 24 3c c7 44 24 3c 00 00 00 00 48 89 44 24 28 c7 44 24 20 00 00 00 00 ff 15 2e 50 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {48 83 ec 38 ff ca 75 1d 48 89 4c 24 28 e8 9a ff ff ff 48 8b 4c 24 28 84 c0 74 0a e8 1c ff ff ff e8 4b ff ff ff b8 01 00 00 00 48 83 c4 38 c3}  //weight: 2, accuracy: High
        $x_2_3 = {55 89 e5 83 ec 18 83 7d 0c 01 75 19 e8 8f ff ff ff 84 c0 74 10 8b 45 08 89 04 24 e8 f8 fe ff ff e8 33 ff ff ff b8 01 00 00 00 c9 c2 0c 00}  //weight: 2, accuracy: High
        $x_2_4 = {89 e5 83 ec 38 8d 45 f4 c7 45 f4 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 20 a0 6a c7 44 24 08 00 24 a0 6a 89 44 24 14 c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00 ff 15 74 60 a0 6a}  //weight: 2, accuracy: High
        $x_1_5 = {01 00 64 6c ?? ?? 2e 64 6c 6c 00 44 6c 6c 4d 61 69 6e [0-5] 00 48 6f 6f 6b 50 72 6f 63}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Turla_AB_2147735227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Turla.AB"
        threat_id = "2147735227"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Turla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\projects\\cuspidPowershell\\cuspid\\EmbeddedDlls\\AMSIFinder\\AMSIFinder\\obj\\Release\\AMSIFinder.pdb" ascii //weight: 1
        $x_1_2 = "dc772b4c-e262-47a7-a956-ac6a2b08f816" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

