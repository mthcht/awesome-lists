rule Trojan_Win32_Meralifea_A_2147728403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meralifea.A"
        threat_id = "2147728403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meralifea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mpi " ascii //weight: 1
        $x_2_2 = {66 81 39 4e 45}  //weight: 2, accuracy: High
        $x_1_3 = "Ewrk" ascii //weight: 1
        $x_2_4 = "\\usbddghci" ascii //weight: 2
        $x_1_5 = "\\UsbgKrnl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Meralifea_A_2147728403_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meralifea.A"
        threat_id = "2147728403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meralifea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8e 4e 0e ec}  //weight: 1, accuracy: High
        $x_1_2 = {aa fc 0d 7c}  //weight: 1, accuracy: High
        $x_1_3 = {66 81 38 4e 45}  //weight: 1, accuracy: High
        $x_1_4 = {66 81 78 02 64 86}  //weight: 1, accuracy: High
        $x_1_5 = {66 81 78 02 4c 01}  //weight: 1, accuracy: High
        $x_3_6 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e0" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Meralifea_A_2147728403_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meralifea.A"
        threat_id = "2147728403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meralifea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/etc/atmfont.bin" ascii //weight: 2
        $x_1_2 = "NamedEscape" ascii //weight: 1
        $x_1_3 = {de de de de 0f 84}  //weight: 1, accuracy: High
        $x_2_4 = "usercls348_Mainwindow" ascii //weight: 2
        $x_1_5 = {38 86 0b 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 6b 74 72 61 70 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 61 74 6d 66 64 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_2_8 = "\\LiptonMilkTea" ascii //weight: 2
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

rule Trojan_Win32_Meralifea_A_2147728403_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meralifea.A"
        threat_id = "2147728403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meralifea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 f8 6a 04 50 89 5d dc 89 5d e0 89 5d e4 ff 55 e8 85 c0 0f 84 ?? ?? 00 00 c7 45 fc 01 00 00 00 83 c6 3a 6a 3a}  //weight: 1, accuracy: Low
        $x_1_2 = {83 7d fc 04 72 81 39 5d f8 0f 84 ea 00 00 00 53 53 53 6a 04 ff 75 f8 ff 15 ?? ?? ?? ?? 8b f0 3b f3 0f 84 a8 00 00 00 81 3e 54 41 64 70 0f 85 95 00 00 00 8b 46 18 6a 40 05 00 04 00 00 68 00 10 00 00}  //weight: 1, accuracy: Low
        $x_2_3 = {89 47 08 8b 46 18 8b 55 08 89 47 18 c7 47 14 19 00 00 00 8d 4c 38 18 8a 46 10 88 01 8b 47 18 03 c7 89 10 8b 56 08 89 50 08 8b 56 0c 89 50 0c 8b 56 04 89 50 04 89 58 10 89 48 14 56 ff 15}  //weight: 2, accuracy: High
        $x_2_4 = {53 00 54 00 4d 00 00 00 20 00 53 00 54 00 4d 00 00 00 00 00 6e 74 64 6c 6c 00 00 00 5a 77 4f 70 65 6e 53 65 63 74 69 6f 6e 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Meralifea_A_2147728403_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meralifea.A"
        threat_id = "2147728403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meralifea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 59 3b f3 89 75 f8 0f 84 ?? ?? 00 00 8d 45 f0 53 50 ff 75 f0 56 ff 75 f4 ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? 00 00 66 81 3e 4d 5a}  //weight: 1, accuracy: Low
        $x_1_2 = {81 7c 24 04 fe ca 00 00 75 12 8b 44 24 14 85 c0 74 0a c7 00 ?? ?? ?? ?? 33 c0 eb 05 b8 02 00 00 c0 c2 18 00}  //weight: 1, accuracy: Low
        $x_2_3 = {6a 10 ff 75 10 8d 45 0c 6a 04 50 68 2c 00 22 00 ff 75 08 ff 15 ?? ?? ?? ?? f7 d8 1b c0 5b 25 ?? ?? ?? ?? 05}  //weight: 2, accuracy: Low
        $x_1_4 = {3d 8e 4e 0e ec 59 75 13 8b 45 08 8b 4d 0c 0f b7 00 8b 04 87 03 c3 89 41 04 eb 18 3d aa fc 0d 7c 75 11}  //weight: 1, accuracy: High
        $x_1_5 = {83 f8 05 75 05 80 3f e8 74 04 03 f8 eb de 8b 47 01 8d 7c 38 05}  //weight: 1, accuracy: High
        $x_1_6 = {80 3b e8 75 ?? 8b 35 ?? ?? ?? ?? 8d 4d 08 51 8d 43 01 6a 40 6a 04 50 89 45 ?? ff d6}  //weight: 1, accuracy: Low
        $x_2_7 = {75 23 eb 16 83 f8 01 75 11 8a 06 3c cc 74 06 80 7e 01 90 75 05 38 46 01 74 09 03 75 1c eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Meralifea_A_2147728403_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meralifea.A"
        threat_id = "2147728403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meralifea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "hDdk " ascii //weight: 1
        $x_2_2 = {74 09 66 81 39 4e 45 74 09 eb 54 66 81 39 4d 5a 75}  //weight: 2, accuracy: High
        $x_1_3 = {81 38 50 45 00 00 74 07 b8 7b 00 00 c0 eb 0b 89 07 33 c0 eb 05 b8 0d 00 00 c0}  //weight: 1, accuracy: High
        $x_1_4 = {81 7c 24 08 38 01 00 00 53 76 ?? ff 74 24 08 e8 ?? ?? ff ff 85 c0 74 ?? 33 db 66 81 78 18 0b 01 75}  //weight: 1, accuracy: Low
        $x_1_5 = "hKAPC" ascii //weight: 1
        $x_1_6 = {68 fe ca 00 00 6a 54 56 ff 15}  //weight: 1, accuracy: High
        $x_2_7 = {8a 0b 80 f9 e9 74 0e 80 f9 e8 74 09 03 f8 03 d8 83 ff 05 72 ?? 83 ff 05 72 ?? 8b 5d 10 33 c9 8b c3 80 38 e9}  //weight: 2, accuracy: Low
        $x_2_8 = {80 3b e8 75 07 8b 4b 01 8d 7c 19 05 85 ff 74 03 ff 45 fc 83 f8 03 75 07 66 81 3b c2 1c}  //weight: 2, accuracy: High
        $x_2_9 = {66 81 3e ff 15 75 06 8b 4e 02 89 4d fc 83 7d fc 00 0f 84 ?? ?? 00 00 ff 45 10 83 7d 10 14 73 ?? 83 f8 06 75 ?? 66 81 3e c7 01}  //weight: 2, accuracy: Low
        $x_1_10 = "\\Systemroot\\system32\\drivers\\%wZ" ascii //weight: 1
        $x_1_11 = "dump_dumpfve.sys" ascii //weight: 1
        $x_1_12 = "\\NPF-{0179AC45-C226-48e3-A205-DCA79C824051}" ascii //weight: 1
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

rule Trojan_Win32_Meralifea_A_2147728403_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meralifea.A"
        threat_id = "2147728403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meralifea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 30 00 22 00 ff 33 ff 15 ?? ?? ?? ?? 85 c0 74 ?? ff 75 ?? ff 15 ?? ?? ?? ?? 68 10 27 00 00 ff 75 ?? ff 15 ?? ?? ?? ?? 85 c0 75 1d 8d 45 0c 50 ff 75 ?? ff 15 ?? ?? ?? ?? 81 7d 0c dd cc bb aa}  //weight: 2, accuracy: Low
        $x_2_2 = {68 00 00 07 00 50 c7 46 1c 00 00 10 00 ff d7 85 c0 74 06 8b 45 ?? 89 46 24 8d 45 fc 53 50 8d 45 f4 6a 08 50 53 53 68 5c 40 07 00 ff 36 ff d7}  //weight: 2, accuracy: Low
        $x_2_3 = {68 20 00 22 00 ff 36 ff d7 85 c0 75 03 89 5d f8 81 7d f8 be ba fe ca}  //weight: 2, accuracy: High
        $x_3_4 = {68 00 20 49 82 53 89 7d fc ff 15 ?? ?? ?? ?? 85 c0 74 0f 33 c0 81 7d fc 46 55 53 45}  //weight: 3, accuracy: Low
        $x_2_5 = {8b 45 10 8b 4e 24 8b 40 08 03 85 ?? ?? ff ff f7 e1 66 81 bd ?? ?? ff ff 55 aa 89 45 f0 89 55 f4 75}  //weight: 2, accuracy: Low
        $x_1_6 = {81 c7 00 00 20 00 83 d2 00 3b d0 77 24 72 04 3b f9 77 1e 8b 7d 10 81 e9 00 00 10 00}  //weight: 1, accuracy: High
        $x_3_7 = {66 81 b8 fe 01 00 00 55 aa 75 74 32 c9 33 d2 05 ca 01 00 00 83 78 fc 00 74 12 83 38 00 74 0d 8a 48 f8 46 42 83 c0 10 83 fa 04 72 ?? 83 fe 01 75 ?? 80 f9 ee}  //weight: 3, accuracy: Low
        $x_2_8 = {ff 50 04 8b f0 83 c4 10 85 f6 74 ?? 8b 46 04 53 8d 0c 40 8d 0c 8d 08 00 00 00 3b 4d 08 73 ?? 66 81 3e 38 9a}  //weight: 2, accuracy: Low
        $x_2_9 = {8b 75 08 57 80 7e 21 be 0f 85 ?? ?? 00 00 80 7e 02 08 0f 85 fb 00 00 00 66 81 7e 06 00 04 0f 83 ef 00 00 00 8b 7d 0c 83 ff 2d}  //weight: 2, accuracy: Low
        $x_2_10 = {74 14 80 3e ef 75 0f 80 7e 01 bb 75 09 80 7e 02 bf}  //weight: 2, accuracy: High
        $x_2_11 = "/arksig.js" ascii //weight: 2
        $x_1_12 = "/bin/i386/dump.bin" ascii //weight: 1
        $x_1_13 = "/bin/i386/kernel.bin" ascii //weight: 1
        $x_1_14 = "/bin/i386/kernel.sig" ascii //weight: 1
        $x_1_15 = "/boot/boot.cfg" ascii //weight: 1
        $x_1_16 = "/boot/kernel" ascii //weight: 1
        $x_1_17 = "/etc/crypto.key" ascii //weight: 1
        $x_1_18 = "/etc/original.dat" ascii //weight: 1
        $x_1_19 = "/setup.img" ascii //weight: 1
        $x_2_20 = "/simplified.patch" ascii //weight: 2
        $x_1_21 = "\\\\.\\UsbgKrnl" ascii //weight: 1
        $x_1_22 = "EFI PART" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Meralifea_A_2147728403_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meralifea.A"
        threat_id = "2147728403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meralifea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-rom" ascii //weight: 1
        $x_1_2 = "1fs-" ascii //weight: 1
        $x_1_3 = "!rbx" ascii //weight: 1
        $x_1_4 = "TAdp" ascii //weight: 1
        $x_1_5 = "SQTP" ascii //weight: 1
        $x_1_6 = "RSDS" ascii //weight: 1
        $x_1_7 = "\\UsbgKrnl" ascii //weight: 1
        $x_1_8 = "company-name" ascii //weight: 1
        $x_1_9 = "exit-process" ascii //weight: 1
        $x_1_10 = "file-list" ascii //weight: 1
        $x_1_11 = "file-match" ascii //weight: 1
        $x_1_12 = "fileop.bin" ascii //weight: 1
        $x_1_13 = "FLAG_DISABLED_3DPARTY" ascii //weight: 1
        $x_1_14 = "force-write" ascii //weight: 1
        $x_1_15 = "force_write" ascii //weight: 1
        $x_1_16 = "loadext-url" ascii //weight: 1
        $x_1_17 = "malware.js" ascii //weight: 1
        $x_1_18 = "msexploit.bin" ascii //weight: 1
        $x_1_19 = "PAN_LISTEN" ascii //weight: 1
        $x_1_20 = "payload.bin" ascii //weight: 1
        $x_1_21 = "policy.js" ascii //weight: 1
        $x_1_22 = "prekernel.bin" ascii //weight: 1
        $x_1_23 = "process-name" ascii //weight: 1
        $x_1_24 = "run-url" ascii //weight: 1
        $x_1_25 = "script-file" ascii //weight: 1
        $x_1_26 = "setup-url" ascii //weight: 1
        $x_1_27 = "setup.bin" ascii //weight: 1
        $x_1_28 = "SETUP_LOCAL_UPGRADE" ascii //weight: 1
        $x_1_29 = "signature-match" ascii //weight: 1
        $x_1_30 = "simplified.js" ascii //weight: 1
        $x_1_31 = "SQTP_ADDR" ascii //weight: 1
        $x_1_32 = "vmx_ignore" ascii //weight: 1
        $x_2_33 = "/Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}" ascii //weight: 2
        $x_2_34 = "/Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D6}" ascii //weight: 2
        $x_1_35 = "\\StringFileInfo\\%04x%04x\\CompanyName" ascii //weight: 1
        $x_1_36 = "{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}-plist" ascii //weight: 1
        $x_2_37 = "{BAE49D12-A961-491f-9D79-0A60CCB5FC49}-sc" ascii //weight: 2
        $x_2_38 = "InetCpl.cpl,ClearMyTracksByProcess 8" ascii //weight: 2
        $x_2_39 = "SETUPAPI.DLL,InstallHinfSection DefaultInstall 132 rdpci21.inf" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((15 of ($x_1_*))) or
            ((1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((5 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Meralifea_A_2147728447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meralifea.A!dll"
        threat_id = "2147728447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meralifea"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 46 07 84 c0 74 ?? 8b 4c 24 18 8b 46 20 85 c9 74 02 89 01 a8 07 74 0a c1 e8 03 8d 04 c5 08 00 00 00 8d 4e 10}  //weight: 2, accuracy: Low
        $x_1_2 = {8b c1 8d 14 39 83 e0 07 8a 1c 2a 8a 44 30 08 32 c3 41 88 02 8b 46 10 3b c8 72 e5}  //weight: 1, accuracy: High
        $x_3_3 = {89 29 8b 4e 10 3b c1 72 e6 5d 8b 54 24 1c a1 ?? ?? ?? ?? 56 52 50 ff d7}  //weight: 3, accuracy: Low
        $x_2_4 = {00 43 50 41 49 4c 6f 61 64 00}  //weight: 2, accuracy: High
        $x_2_5 = {00 44 6c 6c 49 6e 73 74 61 6c 6c 20 3d 3d 3e 0a 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

