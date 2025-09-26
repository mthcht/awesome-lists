rule Trojan_Win32_Emotet_A_2147687347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.A"
        threat_id = "2147687347"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 cb 6b 28 af f7 e6 8b c6 2b c2 d1 e8 03 c2 c1 e8 04 6b c0 13 8b ce 2b c8}  //weight: 1, accuracy: High
        $x_1_2 = "%s\\Microsoft\\%c%c%c%S.exe" ascii //weight: 1
        $x_1_3 = {5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c [0-10] 2e 65 78 65 3a 5a 6f 6e 65 2e 49 64 65 6e 74 69 66 69 65 72}  //weight: 1, accuracy: Low
        $x_1_4 = "SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN" ascii //weight: 1
        $x_1_5 = "C:\\!dbg\\spe.log" wide //weight: 1
        $x_1_6 = {72 65 67 3a 5c 75 6e 6b 6e 6f 77 6e [0-10] 66 73 3a 5c 75 6e 6b 6e 6f 77 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Emotet_B_2147687506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.B"
        threat_id = "2147687506"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 28 5e 09 75 ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 74 ?? e8 06 00 81 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {63 61 70 33 32 [0-5] 62 6f 6f 74 [0-5] 62 69 6f 73 [0-5] 61 75 64 69 6f}  //weight: 1, accuracy: Low
        $x_1_3 = "%s\\Microsoft\\%c%c%c%S.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_2147687714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet"
        threat_id = "2147687714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "HkDZ2IVuO_qop.pdb" ascii //weight: 1
        $x_1_2 = {8b 74 24 04 8a 1c 31 2a 1c 15 ?? ?? ?? ?? 8b 54 24 ?? 88 1c 32 83 c6 33}  //weight: 1, accuracy: Low
        $x_1_3 = {89 45 d8 31 d2 f7 f1 8b 4d e8 8b 75 d8 8a 1c 31 2a 1c 15 ?? ?? ?? ?? 8b 55 e4 88 1c 32 83 c6 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Emotet_2147687714_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet"
        threat_id = "2147687714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 04 6b c2 32 f7 d8}  //weight: 1, accuracy: High
        $x_1_2 = {8b 7c 24 04 8a 9c 07 ?? ?? ?? ?? 89 74 24 38 89 54 24 3c 8b 44 24 18 8a 3c 08 28 df 8b 54 24 1c 88 3c 0a 83 c1 33}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4c 24 04 8a 9c 01 ?? ?? ?? ?? 8b 44 24 1c 8a 3c 08 28 df 8b 54 24 18 88 3c 0a 83 c1 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Emotet_C_2147688541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.C"
        threat_id = "2147688541"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 54 87 f1 51 ?? ce e8 ?? ?? ff ff 89 fa b8 02 00 00 00 52 d1 e0 89 c1 89 d8}  //weight: 1, accuracy: Low
        $x_1_2 = "majorchelsea1andFrequestsapplication" wide //weight: 1
        $x_1_3 = "z1e.bmai298RsBS2" ascii //weight: 1
        $x_1_4 = "bof80fTrinityIt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Emotet_C_2147688541_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.C"
        threat_id = "2147688541"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 e6 8b c2 c1 e8 05 33 d2 bf 19 00 00 00 f7 f7 8b c6 c1 e8 05 c1 e9 03 83 c2 61 52 33 d2}  //weight: 2, accuracy: High
        $x_1_2 = {53 6a 05 6a 02 53 53 68 00 00 00 40 56 ff 15 ?? ?? ?? ?? 8b f8 83 ff ff}  //weight: 1, accuracy: Low
        $x_2_3 = {25 00 73 00 5c 00 6d 00 73 00 25 00 75 00 2e 00 62 00 61 00 74 00 00 00}  //weight: 2, accuracy: High
        $x_1_4 = {25 00 73 00 5c 00 49 00 64 00 65 00 6e 00 74 00 69 00 74 00 69 00 65 00 73 00 5c 00 25 00 63 00 25 00 63 00 25 00 63 00 25 00 63 00 25 00 63 00 25 00 63 00 25 00 63 00 25 00 63 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_C_2147688541_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.C"
        threat_id = "2147688541"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "vbarvulnerabilitiesJazayeri" ascii //weight: 1
        $x_1_2 = "ZbutTorrentFreakAprilCIA" wide //weight: 1
        $x_1_3 = "S168downloaded" wide //weight: 1
        $x_1_4 = {55 54 89 e8 83 c0 10 31 c9 89 da ?? ?? ?? ?? ?? 00 09 d0 83 c1 04 83 f8 00 74 21 5a 01 ca ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 00 83 f9 00 ?? ?? ?? ?? ff ff 85 c0 74 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Emotet_C_2147688541_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.C"
        threat_id = "2147688541"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 78 10 0b 00 04 3d 75 09 33 c9 66 3b 48 18 0f 95 c3 b9}  //weight: 1, accuracy: High
        $x_1_2 = {8a 08 80 f9 2f 74 0a 80 f9 5c 74 05 80 f9 3a 75 01}  //weight: 1, accuracy: High
        $x_1_3 = {2f 69 6e 2f 67 6f 2e 70 68 70 00 [0-16] 2e 70 77 00}  //weight: 1, accuracy: Low
        $x_1_4 = {25 73 3f 69 64 3d 25 73 [0-8] 50 4f 53 54}  //weight: 1, accuracy: Low
        $x_1_5 = {5c 43 6c 69 65 6e 74 73 5c 4d 61 69 6c 5c 00 00 44 4c 4c 50 61 74 68 45 78 00}  //weight: 1, accuracy: High
        $x_1_6 = {7b 5c 2a 5c 68 74 6d 6c 74 61 67 00 5c 2a 5c 68 74 6d 6c 74 61 67 00}  //weight: 1, accuracy: High
        $x_1_7 = "\\spam\\export_email_outlook\\" ascii //weight: 1
        $x_1_8 = "\\maildemo-poisk email v outlook\\" ascii //weight: 1
        $x_1_9 = {2f 6d 33 2f 64 61 74 61 2e 70 68 70 00 [0-16] 2e (72 75|63 6f 2e) 00}  //weight: 1, accuracy: Low
        $x_1_10 = "/input/in/index.php" ascii //weight: 1
        $x_1_11 = "/input/in/Nwh37qAR.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Emotet_D_2147689950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.D"
        threat_id = "2147689950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sNQ.pdb" ascii //weight: 1
        $x_1_2 = "ttbw Ga Pr NUcwblgc Ahwm Jzb" wide //weight: 1
        $x_1_3 = "DVtoU" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_D_2147689950_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.D"
        threat_id = "2147689950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 1c 0e 33 da 69 db 01 01 01 01 41 8b d3 3b c8 72 ed}  //weight: 1, accuracy: High
        $x_1_2 = {b8 1f 85 eb 51 f7 e1 c1 ea 03 8a c2 6b d2 0d b3 19 f6 eb 2a c8 80 c1 61 88 0e 46 83 ef 01 8b ca 75 de}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 14 32 30 14 38 40 fe c3 3b 44 24 18 72 be}  //weight: 1, accuracy: High
        $x_1_4 = "%s\\Identities\\%c%c%c%c%c%c%c%c.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Emotet_E_2147690026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.E"
        threat_id = "2147690026"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 1d 24 4d 47 00 a3 14 4d 47 00 55 a3 18 4d 47 00 a1 5c 4e 47 00 54 8b 00 89 1d 1c 4d 47 00 8f 05 24 4d 47 00 8b 00 83 05 24 4d 47 00 04 8f 05 20 4d 47 00 50 89 35 14 4d 47 00 89 3d 18 4d 47 00 ff e0}  //weight: 1, accuracy: High
        $x_1_2 = "y:\\job\\temp03291.doc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_F_2147690127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.F"
        threat_id = "2147690127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "i2222cfour-partWeGoogleChrome" ascii //weight: 1
        $x_1_2 = "Benchmark8support9norelease(but" ascii //weight: 1
        $x_1_3 = "8ofsuckittheExplorerOqjournalsc" ascii //weight: 1
        $x_1_4 = "College0GovernmenttosettingsPuapproximatelydefaultupdates" wide //weight: 1
        $x_1_5 = "qinformation2016,rseeMyear.40g99" wide //weight: 1
        $x_1_6 = "2TqEeither.113insteada3V43" ascii //weight: 1
        $x_4_7 = "wRHWRH@4hjethwehgw.pdb" ascii //weight: 4
        $x_1_8 = "yiTnumbersVwhetherNovemberU14,y" wide //weight: 1
        $x_1_9 = "W3C,in 2010zggorganizationGbe" ascii //weight: 1
        $x_1_10 = "JdeanZaPAllisolation,1465" wide //weight: 1
        $x_4_11 = "CHmuTmktYyL.pdb" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_F_2147690127_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.F"
        threat_id = "2147690127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 0c 8b 4c 24 2c ba ?? ?? ?? ?? 29 ca 31 c9 89 44 24 08 89 54 24 04 89 ca 8b 4c 24 04 f7 f1 8b 44 24 20 8b 4c 24 08 8a 1c 08 8a ba ?? ?? ?? ?? 28 fb c7 44 24 34 ff ff ff ff c7 44 24 30 ?? ?? ?? ?? 8b 54 24 1c 88 1c 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_G_2147691939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.G"
        threat_id = "2147691939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 33 e8 00 00 00 00 83 04 24 05 cb 4c 8b 55 08 41 8b 42 3c}  //weight: 1, accuracy: High
        $x_1_2 = {8a 04 16 32 81 ?? ?? ?? ?? 41 88 02 83 f9 ?? 72 02}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 00 e9 8b d7 2b 54 24 30 81 c6 ff 0f 00 00 83 ea 55 89 50 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_G_2147691939_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.G"
        threat_id = "2147691939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f1 8a 0c 15 ?? ?? ?? ?? 89 7c 24 ?? 8b 54 24 ?? 8a 2c 1a 8b 7c 24 ?? 8b 54 24 ?? 29 d7 89 7c 24 ?? 28 cd 80 f5 ?? 8b 7c 24 ?? 89 7c 24 ?? 8b 54 24 ?? 88 2c 1a 01 f3 89 5c 24 ?? 8b 74 24 ?? 39 f3 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_G_2147691939_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.G"
        threat_id = "2147691939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {79 09 81 ce 00 30 00 00 89 70 25 80 7c 24 ?? 00 75 44 8a 4c 24 ?? 80 c1 27 80 f9 06}  //weight: 1, accuracy: Low
        $x_1_2 = {69 c9 0d 66 19 00 0f be d2 40 8d 8c 11 5f f3 6e 3c 8a 10 84 d2 75 e9}  //weight: 1, accuracy: High
        $x_1_3 = {bf 37 7e 13 a4 64 a1 30 00 00 00 8b 48 0c 56 8b 71 0c 83 7e 18 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_G_2147691939_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.G"
        threat_id = "2147691939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 25 49 92 24 f7 e6 2b f2 d1 ee 03 f2 c1 ee 03 56}  //weight: 1, accuracy: High
        $x_10_2 = "%s\\Microsoft\\msdb%x.exe" wide //weight: 10
        $x_10_3 = {0f b6 1c 0a 33 de 69 db 01 01 01 01 41 8b f3 3b c8 72 ed 5b}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_G_2147691939_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.G"
        threat_id = "2147691939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 16 32 81 ?? ?? ?? ?? 41 88 02 83 f9 (08|2d|0c) 72 02 33 c9 42 83 ed 01 75 e7}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 1c 0a 33 de 69 db 01 01 01 01 41 8b f3 3b c8 72 ed 5b}  //weight: 1, accuracy: High
        $x_1_3 = {41 66 0f b6 c0 66 89 04 56 83 f9 08 72 02 33 c9 8a 81 ?? ?? ?? ?? 32 82 ?? ?? ?? ?? 41 66 0f b6 c0 66 89 44 56 02 83 f9 08 72 02 33 c9 83 c2 02 83 fa 0e 72 bf}  //weight: 1, accuracy: Low
        $x_1_4 = {79 09 81 ce 00 30 00 00 89 70 25 80 7c 24 ?? 00 75 44 8a 4c 24 ?? 80 c1 27 80 f9 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Emotet_G_2147691939_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.G"
        threat_id = "2147691939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {35 83 2c 17 04 bb ff ff 00 00 f7 f3 8b c1 35 8a 89 ff c4 52 8b d1 81 f2 ae 75 70 6b 52 33 d2 f7 f3 8b c1 35 db 8b 81 a4 52 33 d2 f7 f3 8b c1 35 cb cc 7b 9b 81 f1 3d ed bc 3b 52 33 d2 f7 f3}  //weight: 10, accuracy: High
        $x_10_2 = {8a 1c 17 32 99 ?? ?? ?? ?? 41 88 1a 83 f9 15 72 02 33 c9 8a 1c 2a 32 99 ?? ?? ?? ?? 41 88 5a 01 83 f9 15 72 02 33 c9 8a 1c 10 32 99 ?? ?? ?? ?? 41 88 5a 02 83 f9 15 72 02 33 c9}  //weight: 10, accuracy: Low
        $x_1_3 = {79 09 81 ce 00 30 00 00 89 70 25 80 7c 24 ?? 00 75 44 8a 4c 24 ?? 80 c1 27 80 f9 06}  //weight: 1, accuracy: Low
        $x_1_4 = "%s\\{%08X-%04X-%04X-%04X-%08X%04X}.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_H_2147692223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.H"
        threat_id = "2147692223"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 32 31 32 2e 37 31 2e 32 35 35 2e [0-3] 3a 34 34 33 2f [0-32] 2f 73 6d 74 70 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_2 = "\"%s\" /c \"%s\"" wide //weight: 1
        $x_1_3 = "\"%s\" %s \"%s\"" ascii //weight: 1
        $x_1_4 = {8a 04 16 32 81 ?? ?? ?? ?? 41 88 02 83 f9 ?? 72 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_H_2147692223_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.H"
        threat_id = "2147692223"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "9W1jZbeihy&xB^tUlmF" ascii //weight: 4
        $x_4_2 = "1.pdb" ascii //weight: 4
        $x_4_3 = "liquid\\Brother\\ArmChart.pdb" ascii //weight: 4
        $x_4_4 = {8b 44 24 14 31 c9 8a 14 05 ?? ?? ?? ?? 2a 14 05 ?? ?? ?? ?? 88 54 04 ?? 83 c0 01 83 f8 0b 89 44 24 ?? 89 4c 24 ?? 75 d8}  //weight: 4, accuracy: Low
        $x_9_5 = {8b 44 24 04 8b 4c 24 18 81 e1 ?? ?? ?? ?? 89 c2 83 e2 0f 89 4c 24 18 c7 44 24 1c 00 00 00 00 8a 9a ?? ?? ?? ?? 8b 4c 24 0c 8a 3c 01 28 df 8b 54 24 08 88 3c 02}  //weight: 9, accuracy: Low
        $x_5_6 = {8d 74 0e 05 89 35 08 90 42 00 c7 05 ?? ?? ?? ?? 00 00 00 00 8b f1 0f af f7 8d 74 06 01 0f af f1 0f b7 fe 0f b7 f7 81 c3 ?? ?? ?? ?? 8d ac 0e 51 ff ff ff 81 fd ?? ?? ?? ?? 89 1a}  //weight: 5, accuracy: Low
        $x_9_7 = {8b 44 24 10 89 84 24 ?? 00 00 00 8b 4c 24 0c 89 8c 24 ?? 00 00 00 8b 54 24 6c 8a 1c 15 ?? ?? ?? ?? 8a 3c 15 ?? ?? ?? ?? 28 df 88 7c 14 34 83 c2 01 89 54 24 6c 83 fa 0e 75 c6}  //weight: 9, accuracy: Low
        $x_1_8 = {f2 0f 10 44 04 ?? 66 0f 60 c0 66 0f 71 e0 08 f3 0f 7f}  //weight: 1, accuracy: Low
        $x_1_9 = {e8 ad ff ff ff 83 f9 02 89 45 fc 74 10 e8 a0 ff ff ff e8 ?? ?? ff ff 81 fc f0 ff 00 00 31 c0 c3}  //weight: 1, accuracy: Low
        $x_1_10 = {68 63 0d 00 00 68 ?? ?? ?? 00 89 44 24 ?? ff d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 1 of ($x_1_*))) or
            ((3 of ($x_4_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_9_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_I_2147692730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.I"
        threat_id = "2147692730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {83 c1 4a 3b 0d 40 20 47 00 75 1b 8b 15 08 20 47 00 83 c2 21 2b 15 40 20 47 00}  //weight: 10, accuracy: High
        $x_10_2 = {89 0d 04 20 47 00 8b 15 08 20 47 00 69 d2 bb e3 00 00 2b 15 38 20 47 00}  //weight: 10, accuracy: High
        $x_10_3 = {8b 15 04 20 47 00 69 d2 bb e3 00 00 2b 15 40 20 47 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Emotet_I_2147692730_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.I"
        threat_id = "2147692730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "wh@##weh.Pdb" ascii //weight: 1
        $x_1_2 = "RSDS" ascii //weight: 1
        $x_1_3 = {55 89 e5 50 b8 ?? ?? ?? ?? 31 c9 89 c2 81 ea e8 03 00 00 0f 47 c8 89 c8 89 55 fc 83 c4 04 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_K_2147720894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.K"
        threat_id = "2147720894"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {55 54 89 1d bc ?? ?? 00 8f 05 c4 ?? ?? 00 83 05 c4 ?? ?? 00 08 83 2d c4 ?? ?? 00 04 8f 05 c0 ?? ?? 00 a1 c8 ?? ?? 00 83 05 c4 ?? ?? 00 04 83 2d c4 ?? ?? 00 04 89 35 b4 ?? ?? 00 89 3d b8 ?? ?? 00 ff e0 cc ff 25}  //weight: 8, accuracy: Low
        $x_1_2 = {b9 00 d0 00 00 [0-32] c7 04 24 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 04 24 00 00 00 00 [0-32] c7 44 24 04 00 d0 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 44 24 04 00 d0 00 00 [0-32] c7 44 24 0c 40 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {c7 40 0c 40 00 00 00 [0-32] c7 40 08 00 10 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {c7 40 04 00 d0 00 00 [0-32] c7 00 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_K_2147720894_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.K"
        threat_id = "2147720894"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 e4 33 c0 33 c9 8d 64 24 00 3d 40 af a6 00 76 0d 81 fa 0f 2c 02 00 74 05 b9 6c 00 00 00 40 83 f9 6c 75 e6}  //weight: 1, accuracy: High
        $x_1_2 = {8a 04 1e 88 04 3e 46 3b 75 f8 72 e0 8d 45 f8 8b d7 e8 ?? ?? ff ff ff 55 f0 5f 5e 33 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 3c 02 33 f7 2b ce be 01 00 00 00 81 c2 47 86 c8 61 29 75 fc 75 b2 8b 55 f8 89 0a 89 42 04 83 c2 08 29 75 f4 89 55 f8 75 8e}  //weight: 1, accuracy: High
        $x_3_4 = {6a 00 ff d7 81 fe cb 24 19 00 7e 1f 81 7d f0 e4 86 00 00 74 16 81 7d f0 1c 23 01 00 74 0d 0f b7 45 c8 3d 40 e2 01 00 74 02}  //weight: 3, accuracy: High
        $x_1_5 = "C:\\Bosdisamsadpfaskfmn.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_K_2147720894_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.K"
        threat_id = "2147720894"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 5e c1 ef 02 33 c0 53 33 db 8d 14 be 8b fa 2b fe 83 c7 03 c1 ef 02 3b f2 0f 47 f8 85 ff 74 37}  //weight: 1, accuracy: High
        $x_1_2 = {8d 49 08 33 55 08 8d 76 04 0f b6 c2 43 66 89 41 f8 8b c2 c1 e8 08 0f b6 c0 66 89 41 fa c1 ea 10 0f b6 c2 66 89 41 fc c1 ea 08 0f b6 c2 66 89 41 fe 3b df 72 c9}  //weight: 1, accuracy: High
        $x_1_3 = {8d 44 24 0c ba 0c 00 00 00 50 68 ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ff ff 8b ?? 24 14 83 c4 08 ?? ff 15 ?? ?? ?? ?? 85 c0 74 1b 68}  //weight: 1, accuracy: Low
        $x_1_4 = {8d 45 f8 ba 0c 00 00 00 50 68 ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 75 f8 68}  //weight: 1, accuracy: Low
        $x_1_5 = {83 c0 04 c7 85 cc fb ff ff 04 01 00 00 89 85 c4 fb ff ff 57 c7 00 00 00 00 00 8d 85 dc fb ff ff 50 68 ?? ?? ?? ?? e8 be db ff ff 8d 85 d0 fb ff ff ba 28 00 00 00 50 68}  //weight: 1, accuracy: Low
        $x_1_6 = {8d 45 f8 ba 04 00 00 00 50 68 ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 75 f8 8d ?? ?? ?? ?? ff 68}  //weight: 1, accuracy: Low
        $x_1_7 = {75 2a 8d 04 5d 02 00 00 00 50 8d ?? ?? ?? ?? ff 50 6a 01 6a 00 68 ?? ?? ?? ?? ff 75 f4 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Emotet_M_2147721453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.M!bit"
        threat_id = "2147721453"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 fc 50 6a 40 68 ?? ?? ?? 00 8b 4d f4 51 ff 15 ?? ?? ?? 01 ff 55 f4}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d 0c 8b 11 89 55 ?? 8b 45 0c 8b 48 04 89 4d ?? 8b 55 0c 8b 42 08 89 45 ?? 8b 4d 0c 8b 51 0c}  //weight: 1, accuracy: Low
        $x_1_3 = {c1 e0 04 03 45 f8 8b 4d f4 03 4d f0 33 c1 8b 55 f4 c1 ea 05 03 55 ?? 33 c2 8b 4d ?? 2b c8 89 4d ?? 8b 55 f0 2b 55 ?? 89 55 f0 eb 9e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_L_2147721524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.L!bit"
        threat_id = "2147721524"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f4 03 45 e8 8b 4d f8 03 4d e8 8a 11 88 10 eb dd}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d dc c1 e1 04 03 4d e8 8b 55 dc 03 55 f0 33 ca 8b 45 dc c1 e8 05 03 45 ec 33 c8 8b 55 f4 2b d1 89 55 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_N_2147722776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.N"
        threat_id = "2147722776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/3megfv938ds21m9697282868bnsh73jd/index.php" ascii //weight: 1
        $x_1_2 = "213.155.227.118" ascii //weight: 1
        $x_1_3 = "SvcService" wide //weight: 1
        $x_1_4 = "\\setup.exe" ascii //weight: 1
        $x_1_5 = {63 3d 25 73 [0-16] 63 6f 6e 74 65 6e 74 2d 74 79 70 65 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_O_2147723052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.O!bit"
        threat_id = "2147723052"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 83 f8 41 72 0e 66 83 f8 5a 77 08 0f b7 c0 83 c0 20 eb 03 0f b7 c0 69 d2 ?? ?? ?? ?? 03 d0 83 c1 02 0f b7 01}  //weight: 1, accuracy: Low
        $x_1_2 = {64 a1 30 00 00 00 53 56 57 8b 78 0c 8b d9 83 c7 0c 8b 37}  //weight: 1, accuracy: High
        $x_1_3 = {0f be c0 03 c8 42 8a 02 84 c0 75 ee 8b 45 f8 33 4d 0c 33 ff}  //weight: 1, accuracy: High
        $x_1_4 = {c1 ef 02 33 c0 8d 0c bb 8b fe 8b d1 2b d3 83 c2 03 c1 ea 02 3b d9 0f 47 d0 85 d2 74 3b}  //weight: 1, accuracy: High
        $x_1_5 = {8d 5b 04 33 4d 08 0f b6 c1 66 89 07 8b c1 c1 e8 08 8d 7f 08 0f b6 c0 66 89 47 fa c1 e9 10 0f b6 c1 c1 e9 08 46 66 89 47 fc 0f b6 c1 66 89 47 fe 3b f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Emotet_L_2147723082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.L"
        threat_id = "2147723082"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sqkSKzQamDksuYgu" wide //weight: 1
        $x_1_2 = "gwHJl9LLw.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_L_2147723082_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.L"
        threat_id = "2147723082"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {52 53 44 53 [0-21] 6d 68 7a 33 70 2e 70 64 62}  //weight: 2, accuracy: Low
        $x_2_2 = {52 53 44 53 [0-21] 67 72 72 2a 2a 30 28 31 73 2e 70 64 62}  //weight: 2, accuracy: Low
        $x_2_3 = {58 49 70 6f 57 62 65 71 6f 62 4d 62 77 5a 50 68 [0-32] 6a 00 52 00 74 00 41 00 6b 00 43 00 62 00 72 00 78 00 7a 00 74 00 6e 00 68 00 72 00 78 00 6e 00}  //weight: 2, accuracy: Low
        $x_1_4 = "gpoWBOIIhdTmgSkW" ascii //weight: 1
        $x_1_5 = "FgUyubjeTiFqQoCP" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_L_2147723082_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.L"
        threat_id = "2147723082"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dfsgdfhdfghdfgh.jpg" ascii //weight: 1
        $x_1_2 = {47 43 54 4c 00}  //weight: 1, accuracy: High
        $x_1_3 = {50 ff 15 1c c0 00 03 81 ff 75 f7 0f 00 7e [0-9] 81 fb 4f b7 23 00 74 0d 33 c0 81 7c 24 68 c5 90 0f 45 f0 47 85 f6 75 ?? 89 74 24 10 c7 44 24 10 ?? ?? ff 74 24 10 56 ff 15 14 c0 00 03 8b c8 89 0d 70 35 01 03 39 74 24 10 76 ?? 8b 3d 04 c0 00 03}  //weight: 1, accuracy: Low
        $x_1_4 = {55 8b ec 51 53 8b d9 56 57 89 5d fc 8b 33 8b 53 04 e8 6a 00 00 00 8b f8 bb 20 00 00 00 0f 1f 00 8b ce 8b c6 c1 e9 05 03 0d ?? ?? ?? ?? c1 ?? ?? 03 05 ?? ?? ?? ?? 33 c8 8d ?? ?? 33 c8 2b d1 8b ca 8b c2 c1 e9 05 03 0d ?? ?? ?? ?? c1 e0 04 03 05 ?? ?? ?? ?? 33 c8 8d 04 17 33 c8 8d bf 47 86 c8 61 2b f1 83 eb 01 75 b7 8b 5d fc 5f 89 33 5e 89 53 04 5b 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Emotet_M_2147723153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.M"
        threat_id = "2147723153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yiTnumbersVwhetherNovemberU14,y" wide //weight: 1
        $x_1_2 = "version v ALFjcsynchronization" wide //weight: 1
        $x_1_3 = "hasbeJavamopen-sourcingfeaturesYNcto" wide //weight: 1
        $x_1_4 = "PAjamesheka6w2Uathatdwindow" wide //weight: 1
        $x_1_5 = "boundaryZ526,replacewithfirstd" ascii //weight: 1
        $x_1_6 = "features20123,John30-dayn9dolphinstiggere" wide //weight: 1
        $x_1_7 = "Mshortcuts(e.g.webotherfirstinstallationIUniversityby" wide //weight: 1
        $x_1_8 = "2009,PrismYanimalonbrowserE" wide //weight: 1
        $x_1_9 = "EWikiLeaks,e.g.Player)ScomponentsMV" wide //weight: 1
        $x_1_10 = "badboytheaweretest,fof" wide //weight: 1
        $x_1_11 = "bStoregoblocked.89fuzzSand7r" wide //weight: 1
        $x_1_12 = "thejlblocked.89Developerwthezjweb" wide //weight: 1
        $x_1_13 = "1234reflectsthat7differentiatingZO" ascii //weight: 1
        $x_1_14 = "KsecurityOmnibox.thoughand(similarthatt" ascii //weight: 1
        $x_1_15 = "H.264Y92012measureonextras.160GoogleC" ascii //weight: 1
        $x_1_16 = "Betagpredictions111ataylorRZfirst" ascii //weight: 1
        $x_1_17 = "E987654covered)twiceTheseisfor" ascii //weight: 1
        $x_1_18 = "wDevhtransitions,6Sjail. 82108, frequent" ascii //weight: 1
        $x_1_19 = "regular dates, twith monster whether of ..." ascii //weight: 1
        $x_1_20 = "9versionpoints.64productLasLWMp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Emotet_M_2147723153_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.M"
        threat_id = "2147723153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 e7 03 83 e7 18 89 4d d4 89 f9 d3 e6 31 c6 8b 45 ec 8a 0c 02 8b 55 f0 88 0a 8b 7d d4 83 c7 01}  //weight: 10, accuracy: High
        $x_10_2 = {15 18 00 00 00 31 ?? 8b ?? 30 8b ?? 0c}  //weight: 10, accuracy: Low
        $x_10_3 = {74 0a a1 18 30 ?? 00 ff d0}  //weight: 10, accuracy: Low
        $x_10_4 = {8b 30 8b 78 04 8b 58 08 8b 68 0c 8b 60 10 8b 40 14 ff e0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_M_2147723153_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.M"
        threat_id = "2147723153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {55 54 89 1d ?? 50 40 00 8f 05 ?? 50 40 00 83 05 ?? 50 40 00 08 83 2d ?? 50 40 00 04 8f 05 ?? 50 40 00 a1 ?? 50 40 00 83 05 ?? 50 40 00 04 83 2d ?? 50 40 00 04 89 35 ?? 50 40 00 89 3d ?? 50 40 00 ff e0 cc}  //weight: 8, accuracy: Low
        $x_1_2 = {c7 04 24 00 00 00 00 [0-32] c7 44 24 08 00 10 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {ba 00 10 00 00 ?? ?? 00 00 00 [0-48] c7 04 24 00 00 00 00 [0-32] c7 44 24 08 00 10 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {ba 00 10 00 00 [0-32] c7 04 24 00 00 00 00 [0-32] c7 44 24 08 00 10 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {c7 42 0c 40 00 00 00 [0-32] c7 42 04 00 d0 00 00 [0-32] c7 02 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {b9 00 d0 00 00 [0-32] c7 04 24 00 00 00 00 [0-32] c7 44 24 04 00 d0 00 00}  //weight: 1, accuracy: Low
        $x_1_7 = {ba 00 10 00 00 ?? ?? ?? ?? ?? c7 04 24 00 00 00 00 ?? ?? ?? ?? c7 44 24 04 00 d0 00 00}  //weight: 1, accuracy: Low
        $x_1_8 = {be 40 00 00 00 [0-32] c7 04 24 00 00 00 00 [0-32] c7 44 24 04 00 d0 00 00 [0-32] c7 44 24 08 00 10 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_P_2147723677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.P"
        threat_id = "2147723677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {7c 75 47 54 4a 76 46 7a 54 68 4d 53 55 6a 39 5a 66 2e 70 64 62 18 00 52 53 44 53}  //weight: 10, accuracy: Low
        $x_10_2 = {6b 6f 6c 73 64 65 33 32 2e 64 6c 6c 18 00 52 53 44 53}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_P_2147723677_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.P"
        threat_id = "2147723677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_40_1 = {54 89 e0 83 e8 10 31 c9 89 1d ?? ?? ?? ?? 01 d8 83 c8 01 83 c1 04 83 f8 00 74 24 8f 05 ?? ?? ?? ?? 01 0d ?? ?? ?? ?? 8f 05 ?? ?? ?? ?? 83 f9 00 0f 85 ?? ?? ?? ?? 85 c0 74 05 b8 ff 00 00 00}  //weight: 40, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_P_2147723677_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.P"
        threat_id = "2147723677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 2c 89 44 24 20 89 4c 24 1c 89 54 24 18 89 5c 24 14 89 7c 24 10 89 74 24 0c 8b 44 24 0c 8b 0c 85 ?? ?? ?? ?? 8b 54 24 24 39 d1 89 44 24 08 89 4c 24 04 73 6d 8b 44 24 04 b9 3e 00 00 00 8b 54 24 14 81 e2 ?? ?? ?? ?? 89 54 24 28 c7 44 24 2c 00 00 00 00 89 04 24 31 d2 f7 f1 8b 4c 24 1c 8b 34 24 8a 1c 31 8b 7c 24 24}  //weight: 1, accuracy: Low
        $x_1_2 = {83 f7 ff 8a 7c 24 3b 80 c7 82 89 7c 24 34 8a 0c 15 ?? ?? ?? ?? 00 fb 28 cb 8b 54 24 18 88 1c 32 83 c6 3e 8b 7c 24 24 39 fe 89 74 24 04 72 9d eb 08 8d 65 f4 5f 5b 5e 5d c3 8b 44 24 08 83 c0 01 83 f8 3e 89 44 24 0c 74 e8 e9 63 ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_P_2147723677_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.P"
        threat_id = "2147723677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {ff d0 c7 84 24 88 00 00 00 00 01 00 00 8d 8c 24 ?? 00 00 00 8b 15 ?? ?? ?? ?? 51 8b 4c 24 ?? 51 89 44 24 ?? ff d2}  //weight: 4, accuracy: Low
        $x_3_2 = {ff d0 8b 0d ?? ?? ?? ?? 50 89 44 24 ?? ff d1}  //weight: 3, accuracy: Low
        $x_3_3 = {40 04 00 00 00 c7 ?? 44 02 92 00 00 c7 ?? 48 00 d0 00 00}  //weight: 3, accuracy: Low
        $x_1_4 = "TEQUILABOOMBOOM" ascii //weight: 1
        $x_1_5 = "C:\\Symbols\\aagmmc.pdb" ascii //weight: 1
        $x_1_6 = "KLONE_X64-PC" ascii //weight: 1
        $x_1_7 = "C:\\take_screenshot.ps1" ascii //weight: 1
        $x_1_8 = "C:\\email.doc" ascii //weight: 1
        $x_1_9 = "C:\\123\\email.doc" ascii //weight: 1
        $x_1_10 = "C:\\a\\foobar.bmp" ascii //weight: 1
        $x_3_11 = {8b 44 24 08 66 8b 08 8b 54 24 18 81 ca ?? ?? ?? ?? 8b 74 24 10 89 74 24 2c 89 54 24 28 66 81 f9 4d 5a}  //weight: 3, accuracy: Low
        $x_2_12 = {d3 e2 89 54 24 54 8b 54 24 24 8b 74 24 14 89 72 54 89 42 58 8b 44 24 20 35 ?? ?? ?? ?? 89 44 24 54 81 c6 ?? ?? 00 00 89 74 24 18 eb}  //weight: 2, accuracy: Low
        $x_1_13 = {01 f0 8b 00 8b 37 8b bc 24 84 00 00 00 33 01 01 df 89 e1 89 41 08}  //weight: 1, accuracy: High
        $x_1_14 = {8d 44 24 73 8b 4c 24 5c 81 f1 ?? ?? ?? ?? 89 8c 24 b8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_15 = {8b 44 24 1c 89 44 24 38 8b 7c 24 24 83 c7 58 89 7c 24 20 39 c7}  //weight: 1, accuracy: High
        $x_1_16 = {8b 44 24 20 35 ?? ?? ?? ?? 8b 4c 24 1c 8b 54 24 30 29 d1 0f 95 c3 8a 7c 24 1b 20 df 8b 74 24 28 89 74 24 4c 89 44 24 48}  //weight: 1, accuracy: Low
        $x_1_17 = {89 44 24 2c 8b 44 24 2c 89 44 24 28 8b 44 24 20 8b 4c 24 24 35 ?? ?? ?? ?? 09 c8 c7 44 24 2c 00 00 00 00 89 44 24 0c 74 db eb 00}  //weight: 1, accuracy: Low
        $x_2_18 = {8b 44 24 34 89 e1 8d 54 24 64 89 51 0c 8d 54 24 58 89 51 04 8b 54 24 20 89 11 c7 41 08 00 00 00 00 ff d0}  //weight: 2, accuracy: High
        $x_1_19 = {8b 54 24 30 81 c2 ?? ?? ?? ?? 8b 7c 24 2c 83 d7 00 89 7c 24 7c 89 54 24 78}  //weight: 1, accuracy: Low
        $x_3_20 = {c6 44 24 77 61 8b 8c 24 c0 00 00 00 8b 54 24 44 8b 0c 8a 89 8c 24 c4 00 00 00 69 8c 24 d0 00 00 00 ?? ?? ?? ?? c7 44 24 68 00 00 00 00 c7 44 24 70 ?? ?? ?? ?? 39 c8 74 a4}  //weight: 3, accuracy: Low
        $x_1_21 = {75 02 eb 00 31 c0 8b 4c 24 14 c7 01 00 a2 00 00}  //weight: 1, accuracy: High
        $x_3_22 = {8a 08 8a 54 24 13 28 d1 8b 44 24 18 8b 74 24 1c bf ?? ?? ?? ?? f7 e7 69 f6 ?? ?? ?? ?? 01 f2 89 44 24 18 89 54 24 1c 8b 44 24 04 8b 54 24 0c 88 0c 10}  //weight: 3, accuracy: Low
        $x_1_23 = {ff 75 08 53 ff 36 ff 15 ?? ?? ?? ?? 89 46 04 85 c0 74 0c 33 c0 c7 46 0c 03 00 00 00 40 eb 0a ff 36 ff 15}  //weight: 1, accuracy: Low
        $x_3_24 = {83 7d e0 27 0f 84 ?? ?? 00 00 83 7d e0 28 0f 84 ?? ?? 00 00 83 7d e0 29 0f 84 ?? ?? 00 00 83 7d e0 2a 0f 84 ?? ?? 00 00 83 7d e0 33 0f 84 ?? ?? 00 00 83 7d e0 34 0f 84 ?? ?? 00 00 83 7d e0 35}  //weight: 3, accuracy: Low
        $x_2_25 = {74 3b 33 f6 8b 0b 8d 5b 04 33 4d 08 0f b6 c1 66 89 07}  //weight: 2, accuracy: High
        $x_1_26 = {f7 75 f8 8b d8 03 d6 f7 d3 eb 06 80 3a 2c 74 18 4a 3b d6 77 f6}  //weight: 1, accuracy: High
        $x_2_27 = {03 f7 81 fb 00 fa 00 00 73 08 ff 15 ?? ?? ?? ?? 33 f0 83 c7 12 43 81 ff 00 00 00 90 72 e2 33 c0 81 fe 00 00 00 08}  //weight: 2, accuracy: Low
        $x_1_28 = {74 16 8b cf 2b ce 8b 06 35 ?? ?? ?? ?? 43 89 04 31 8d 76 04 3b da 72 ee}  //weight: 1, accuracy: Low
        $x_3_29 = {75 ee 6a 2e 58 66 89 02 03 d1 6a 44 58 6a 4c}  //weight: 3, accuracy: High
        $x_2_30 = {83 7e 0c 04 89 7d fc 0f 44 d8 39 4d 10 74 1d 8d 45 fc b9 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 6a 04 5a e8 ?? ?? ff ff}  //weight: 2, accuracy: Low
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
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_3_*))) or
            ((1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_P_2147723684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.P!!Emotet.gen!A"
        threat_id = "2147723684"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "Emotet: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {ff d0 c7 84 24 88 00 00 00 00 01 00 00 8d 8c 24 ?? 00 00 00 8b 15 ?? ?? ?? ?? 51 8b 4c 24 ?? 51 89 44 24 ?? ff d2}  //weight: 4, accuracy: Low
        $x_3_2 = {ff d0 8b 0d ?? ?? ?? ?? 50 89 44 24 ?? ff d1}  //weight: 3, accuracy: Low
        $x_3_3 = {40 04 00 00 00 c7 ?? 44 02 92 00 00 c7 ?? 48 00 d0 00 00}  //weight: 3, accuracy: Low
        $x_1_4 = "TEQUILABOOMBOOM" ascii //weight: 1
        $x_1_5 = "C:\\Symbols\\aagmmc.pdb" ascii //weight: 1
        $x_1_6 = "KLONE_X64-PC" ascii //weight: 1
        $x_1_7 = "C:\\take_screenshot.ps1" ascii //weight: 1
        $x_1_8 = "C:\\email.doc" ascii //weight: 1
        $x_1_9 = "C:\\123\\email.doc" ascii //weight: 1
        $x_1_10 = "C:\\a\\foobar.bmp" ascii //weight: 1
        $x_3_11 = {8b 44 24 08 66 8b 08 8b 54 24 18 81 ca ?? ?? ?? ?? 8b 74 24 10 89 74 24 2c 89 54 24 28 66 81 f9 4d 5a}  //weight: 3, accuracy: Low
        $x_2_12 = {d3 e2 89 54 24 54 8b 54 24 24 8b 74 24 14 89 72 54 89 42 58 8b 44 24 20 35 ?? ?? ?? ?? 89 44 24 54 81 c6 ?? ?? 00 00 89 74 24 18 eb}  //weight: 2, accuracy: Low
        $x_1_13 = {01 f0 8b 00 8b 37 8b bc 24 84 00 00 00 33 01 01 df 89 e1 89 41 08}  //weight: 1, accuracy: High
        $x_1_14 = {8d 44 24 73 8b 4c 24 5c 81 f1 ?? ?? ?? ?? 89 8c 24 b8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_15 = {8b 44 24 1c 89 44 24 38 8b 7c 24 24 83 c7 58 89 7c 24 20 39 c7}  //weight: 1, accuracy: High
        $x_1_16 = {8b 44 24 20 35 ?? ?? ?? ?? 8b 4c 24 1c 8b 54 24 30 29 d1 0f 95 c3 8a 7c 24 1b 20 df 8b 74 24 28 89 74 24 4c 89 44 24 48}  //weight: 1, accuracy: Low
        $x_1_17 = {89 44 24 2c 8b 44 24 2c 89 44 24 28 8b 44 24 20 8b 4c 24 24 35 ?? ?? ?? ?? 09 c8 c7 44 24 2c 00 00 00 00 89 44 24 0c 74 db eb 00}  //weight: 1, accuracy: Low
        $x_2_18 = {8b 44 24 34 89 e1 8d 54 24 64 89 51 0c 8d 54 24 58 89 51 04 8b 54 24 20 89 11 c7 41 08 00 00 00 00 ff d0}  //weight: 2, accuracy: High
        $x_1_19 = {8b 54 24 30 81 c2 ?? ?? ?? ?? 8b 7c 24 2c 83 d7 00 89 7c 24 7c 89 54 24 78}  //weight: 1, accuracy: Low
        $x_3_20 = {c6 44 24 77 61 8b 8c 24 c0 00 00 00 8b 54 24 44 8b 0c 8a 89 8c 24 c4 00 00 00 69 8c 24 d0 00 00 00 ?? ?? ?? ?? c7 44 24 68 00 00 00 00 c7 44 24 70 ?? ?? ?? ?? 39 c8 74 a4}  //weight: 3, accuracy: Low
        $x_1_21 = {75 02 eb 00 31 c0 8b 4c 24 14 c7 01 00 a2 00 00}  //weight: 1, accuracy: High
        $x_3_22 = {8a 08 8a 54 24 13 28 d1 8b 44 24 18 8b 74 24 1c bf ?? ?? ?? ?? f7 e7 69 f6 ?? ?? ?? ?? 01 f2 89 44 24 18 89 54 24 1c 8b 44 24 04 8b 54 24 0c 88 0c 10}  //weight: 3, accuracy: Low
        $x_1_23 = {ff 75 08 53 ff 36 ff 15 ?? ?? ?? ?? 89 46 04 85 c0 74 0c 33 c0 c7 46 0c 03 00 00 00 40 eb 0a ff 36 ff 15}  //weight: 1, accuracy: Low
        $x_3_24 = {83 7d e0 27 0f 84 ?? ?? 00 00 83 7d e0 28 0f 84 ?? ?? 00 00 83 7d e0 29 0f 84 ?? ?? 00 00 83 7d e0 2a 0f 84 ?? ?? 00 00 83 7d e0 33 0f 84 ?? ?? 00 00 83 7d e0 34 0f 84 ?? ?? 00 00 83 7d e0 35}  //weight: 3, accuracy: Low
        $x_2_25 = {74 3b 33 f6 8b 0b 8d 5b 04 33 4d 08 0f b6 c1 66 89 07}  //weight: 2, accuracy: High
        $x_1_26 = {f7 75 f8 8b d8 03 d6 f7 d3 eb 06 80 3a 2c 74 18 4a 3b d6 77 f6}  //weight: 1, accuracy: High
        $x_2_27 = {03 f7 81 fb 00 fa 00 00 73 08 ff 15 ?? ?? ?? ?? 33 f0 83 c7 12 43 81 ff 00 00 00 90 72 e2 33 c0 81 fe 00 00 00 08}  //weight: 2, accuracy: Low
        $x_1_28 = {74 16 8b cf 2b ce 8b 06 35 ?? ?? ?? ?? 43 89 04 31 8d 76 04 3b da 72 ee}  //weight: 1, accuracy: Low
        $x_3_29 = {75 ee 6a 2e 58 66 89 02 03 d1 6a 44 58 6a 4c}  //weight: 3, accuracy: High
        $x_2_30 = {83 7e 0c 04 89 7d fc 0f 44 d8 39 4d 10 74 1d 8d 45 fc b9 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 6a 04 5a e8 ?? ?? ff ff}  //weight: 2, accuracy: Low
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
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_3_*))) or
            ((1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_PA_2147724295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PA"
        threat_id = "2147724295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 31 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 8b ff 01 05 ?? ?? ?? ?? 8b ff 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_R_2147724588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.R"
        threat_id = "2147724588"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 e4 f8 83 ec 78 31 c0 66 c7 44 24 72 78 dd c7 44 24 5c 95 13 b3 5d}  //weight: 10, accuracy: High
        $x_10_2 = {66 83 c7 20 66 83 c6 bf 66 83 fe 1a 66 0f 42 df 66 39 da 0f 94 c0 24 01}  //weight: 10, accuracy: High
        $x_10_3 = {bb a3 0c 23 c7 84 [0-5] e4 ac d0 19 c7 84 [0-5] b1 e1 01 5d 8b 8c [0-5] c7 84 [0-5] 0a b0 51 23}  //weight: 10, accuracy: Low
        $x_10_4 = {c0 28 80 41 [0-4] 3d 27 74 00 2e}  //weight: 10, accuracy: Low
        $x_10_5 = {66 c7 44 24 ?? 78 dd c7 44 24 ?? 95 13 b3 5d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Emotet_S_2147724610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.S"
        threat_id = "2147724610"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c7 02 2e 00 44 00 33 c0 c7 42 04 4c 00 4c 00}  //weight: 5, accuracy: High
        $x_5_2 = {c7 45 b4 41 00 44 00 c7 45 b8 4d 00 49 00 c7 45 bc 4e 00 24 00}  //weight: 5, accuracy: High
        $x_5_3 = {c7 85 68 ff ff ff 25 00 53 00 c7 85 6c ff ff ff 79 00 73 00 c7 85 70 ff ff ff 74 00 65 00 c7 85 74 ff ff ff 6d 00 52 00 c7 85 78 ff ff ff 6f 00 6f 00 c7 85 7c ff ff ff 74 00 25 00}  //weight: 5, accuracy: High
        $x_5_4 = {63 00 72 00 [0-2] c7 ?? ?? 79 00 70 00 c7 ?? ?? 74 00 33 00 c7 ?? ?? 32 00 2e 00 c7 ?? ?? 64 00 6c 00}  //weight: 5, accuracy: Low
        $x_5_5 = {6e 00 65 00 [0-4] c7 45 e0 74 00 61 00 c7 45 e4 70 00 69 00 c7 45 e8 33 00 32 00 c7 45 ec 2e 00 64 00 c7 45 f0 6c 00 6c 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Emotet_Q_2147724679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.Q"
        threat_id = "2147724679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 5c 6d 35 46 65 44 62 4d 39 33 54 2e 62 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 67 6d 31 36 48 43 7a 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 69 4d 45 55 57 70 49 66 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_R_2147725043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.R!bit"
        threat_id = "2147725043"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\a\\foobar.bmp" wide //weight: 1
        $x_1_2 = "C:\\123\\email.doc" wide //weight: 1
        $x_1_3 = "C:\\email.doc" wide //weight: 1
        $x_1_4 = "C:\\take_screenshot.ps1" wide //weight: 1
        $x_1_5 = "KLONE_X64-PC" ascii //weight: 1
        $x_1_6 = "C:\\Symbols\\aagmmc.pdb" wide //weight: 1
        $x_1_7 = "TEQUILABOOMBOOM" ascii //weight: 1
        $x_1_8 = {8b 30 8b 78 04 8b 58 08 8b 68 0c 8b 60 10 8b 40 14 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_T_2147725152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.T"
        threat_id = "2147725152"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 61 6d 70 6c 65 00 6d 6c 77 72 5f 73 6d 70 6c 00 61 72 74 69 66 61 63 74 2e 65 78 65 00 63}  //weight: 1, accuracy: High
        $x_1_2 = {54 45 51 55 49 4c 41 42 4f 4f 4d 42 4f 4f 4d 00 57 69 6c 62 65 72 74}  //weight: 1, accuracy: High
        $x_1_3 = {4b 4c 4f 4e 45 5f 58 36 34 2d 50 43 00 4a 6f 68 6e 20 44 6f 65 00 42 45 41 2d 43 48 49}  //weight: 1, accuracy: High
        $x_1_4 = {5c 00 74 00 61 00 6b 00 65 00 5f 00 73 00 63 00 72 00 65 00 65 00 6e 00 73 00 68 00 6f 00 74 00 2e 00 70 00 73 00 31 00 00 00 43 00 3a 00 5c 00 6c 00 6f 00 61 00 64 00 64 00 6c 00 6c 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 00 65 00 6d 00 61 00 69 00 6c 00 2e 00 68 00 74 00 6d 00 00 00 43 00 3a 00 5c 00 31 00 32 00 33 00 5c 00 65 00 6d 00 61 00 69 00 6c 00 2e 00 64 00 6f 00 63 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 00 61 00 5c 00 66 00 6f 00 6f 00 62 00 61 00 72 00 2e 00 64 00 6f 00 63 00 00 00 43 00 3a 00 5c 00 61 00 5c 00 66 00 6f 00 6f 00 62 00 61 00 72 00 2e 00 67 00 69 00 66 00}  //weight: 1, accuracy: High
        $x_1_7 = {62 6f 6f 6b 00 66 61 63 65 00 6c 75 63 6b 00 25 58 25 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_U_2147725200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.U!bit"
        threat_id = "2147725200"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Symbols\\aagmmc.pdb" wide //weight: 1
        $x_1_2 = "KLONE_X64-PC" ascii //weight: 1
        $x_1_3 = "C:\\take_screenshot.ps1" wide //weight: 1
        $x_1_4 = {5c 00 65 00 6d 00 61 00 69 00 6c 00 2e 00 68 00 74 00 6d 00 00 00 43 00 3a 00 5c 00 31 00 32 00 33 00 5c 00 65 00 6d 00 61 00 69 00 6c 00 2e 00 64 00 6f 00 63 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 00 61 00 5c 00 66 00 6f 00 6f 00 62 00 61 00 72 00 2e 00 64 00 6f 00 63 00 00 00 43 00 3a 00 5c 00 61 00 5c 00 66 00 6f 00 6f 00 62 00 61 00 72 00 2e 00 67 00 69 00 66 00}  //weight: 1, accuracy: High
        $x_1_6 = {8d 49 08 33 55 08 8d 76 04 0f b6 c2 43 66 89 41 f8 8b c2 c1 e8 08 0f b6 c0 66 89 41 fa c1 ea 10 0f b6 c2 66 89 41 fc c1 ea 08 0f b6 c2 66 89 41 fe 3b df 72 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_V_2147725280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.V!bit"
        threat_id = "2147725280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {62 6f 6f 6b 00 66 61 63 65 00 6c 75 63 6b 00 25 58 25 50}  //weight: 1, accuracy: High
        $x_1_2 = {89 c1 83 e1 1f 8b 15 ?? ?? ?? ?? 8a 1c 0a 8b 4d ?? 8a 3c 01 28 df 88 3c 01 05 ff 00 00 00 8b 55 ?? 39 d0 89 45 ?? 72}  //weight: 1, accuracy: Low
        $x_1_3 = {eb 23 8b 45 ?? 8b 4d ?? 01 c8 8b 55 ?? 8b 34 ?? 8b 7c 02 04 8b 5d ?? 01 de 8b 4d ?? 11 cf 89 34 02 89 7c 02 04}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 30 8b 78 04 8b 58 08 8b 68 0c 8b 60 10 8b 40 14 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_W_2147725329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.W!bit"
        threat_id = "2147725329"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {62 6f 6f 6b 00 66 61 63 65 00 6c 75 63 6b 00 25 58 25 50}  //weight: 1, accuracy: High
        $x_1_2 = {eb 23 8b 45 ?? 8b 4d ?? 01 c8 8b 55 ?? 8b 34 ?? 8b 7c 02 04 8b 5d ?? 01 de 8b 4d ?? 11 cf 89 34 02 89 7c 02 04}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 30 8b 78 04 8b 58 08 8b 68 0c 8b 60 10 8b 40 14 ff e0}  //weight: 1, accuracy: High
        $x_1_4 = {31 d2 f7 f1 8b 0d ?? ?? ?? ?? 8a 1c 11 8b 4d ?? 8b 55 ?? 8a 3c 11 28 df 88 3c 11 81 c2 ff 00 00 00 8b 75 ?? 39 f2 89 55 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_X_2147726042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.X!bit"
        threat_id = "2147726042"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 23 8b 45 ?? 8b 4d ?? 01 c8 8b 55 ?? 8b 34 ?? 8b 7c 02 04 8b 5d ?? 01 de 8b 4d ?? 11 cf 89 34 02 89 7c 02 04}  //weight: 1, accuracy: Low
        $x_1_2 = {31 d2 f7 f1 8b 0d ?? ?? ?? ?? 8a 1c 11 8b 4d ?? 8b 55 ?? 8a 3c 11 28 df 88 3c 11 81 c2 ff 00 00 00 8b 75 ?? 39 f2 89 55 ?? 72}  //weight: 1, accuracy: Low
        $x_1_3 = "TEQUILABOOMBOOM" ascii //weight: 1
        $x_1_4 = "C:\\take_screenshot.ps1" wide //weight: 1
        $x_1_5 = {5c 00 65 00 6d 00 61 00 69 00 6c 00 2e 00 68 00 74 00 6d 00 00 00 43 00 3a 00 5c 00 31 00 32 00 33 00 5c 00 65 00 6d 00 61 00 69 00 6c 00 2e 00 64 00 6f 00 63 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 00 61 00 5c 00 66 00 6f 00 6f 00 62 00 61 00 72 00 2e 00 64 00 6f 00 63 00 00 00 43 00 3a 00 5c 00 61 00 5c 00 66 00 6f 00 6f 00 62 00 61 00 72 00 2e 00 67 00 69 00 66 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AA_2147726188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AA!bit"
        threat_id = "2147726188"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 23 8b 45 ?? 8b 4d ?? 01 c8 8b 55 ?? 8b 34 ?? 8b 7c 02 04 8b 5d ?? 01 de 8b 4d ?? 11 cf 89 34 02 89 7c 02 04}  //weight: 1, accuracy: Low
        $x_1_2 = {89 c1 83 e1 1f 8b 15 ?? ?? ?? ?? 8a 1c 0a 8b 4d ?? 8a 3c 01 28 df 88 3c 01 05 ff 00 00 00 8b 55 ?? 39 d0 89 45 ?? 72}  //weight: 1, accuracy: Low
        $x_1_3 = {89 f1 01 c1 83 c1 08 8b 01 8b 4d ?? c6 01 ?? 8b 4d ?? 29 cf 8b 4d ?? 01 f9 01 d9 8b 7d ?? 89 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AB_2147726231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AB"
        threat_id = "2147726231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 c9 81 e9 fc a1 29 00 09 c8 83 e8 20 8d 15 78 97 40 00 89 1a 8d 0d b0 be 5c 00 89 fa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AB_2147726231_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AB"
        threat_id = "2147726231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 54 8b 4c 24 54 8a 14 0d ?? ?? ?? ?? 2a 14 05 ?? ?? ?? ?? 8b 44 24 54 88 54 04 2c 8b 44 24 54 83 c0 01 89 44 24 50 83 f8 0e}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 58 89 c1 83 e1 0f 8b 54 24 78 81 f2 4c f4 df 03 8a 1c 0d ?? ?? ?? ?? 8a 3c 05 ?? ?? ?? ?? 28 df c7 44 24 7c ?? ?? ?? ?? 88 7c 04 38 01 d0 89 44 24 58 83 f8 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PB_2147726253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PB!bit"
        threat_id = "2147726253"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 23 8b 45 ?? 8b 4d ?? 01 c8 8b 55 ?? 8b 34 ?? 8b 7c 02 04 8b 5d ?? 01 de 8b 4d ?? 11 cf 89 34 02 89 7c 02 04}  //weight: 1, accuracy: Low
        $x_1_2 = {89 f1 01 c1 83 c1 08 8b 01 8b 4d ?? c6 01 ?? 8b 4d ?? 29 cf 8b 4d ?? 01 f9 01 d9 8b 7d ?? 89 0f}  //weight: 1, accuracy: Low
        $x_1_3 = {31 d2 f7 f1 8b 0d ?? ?? ?? ?? 8a 1c 11 8b 4d ?? 8b 55 ?? 8a 3c 11 28 df 88 3c 11}  //weight: 1, accuracy: Low
        $x_1_4 = {01 c8 8b 55 ?? 8b 34 02 8b 7c 02 04 8b 5d ?? 01 de 8b 4d ?? 11 cf 89 34 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AD_2147726529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AD!bit"
        threat_id = "2147726529"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 69 8b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 88 01 8b 15 ?? ?? ?? ?? 83 c2 6e a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 88 50 01 8b 0d ?? ?? ?? ?? 83 c1 74 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 88 4a 02 a1 ?? ?? ?? ?? 83 c0 65 8b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 88 41 03 8b 15 ?? ?? ?? ?? 83 c2 72 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 88 50 04 8b 0d ?? ?? ?? ?? 83 c1 66 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 88 4a 05 a1 ?? ?? ?? ?? 83 c0 61 8b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 88 41 06 8b 15 ?? ?? ?? ?? 83 c2 63 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 88 50 07 8b 0d ?? ?? ?? ?? 83 c1 65 8b 15}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 5c 8b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 88 41 09 8b 15 ?? ?? ?? ?? 83 c2 7b a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 88 50 0a 8b 0d ?? ?? ?? ?? 83 c1 61 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 88 4a 0b a1 ?? ?? ?? ?? 83 c0 61 8b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 88 41 0c 8b 15 ?? ?? ?? ?? 83 c2 35 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 88 50 0d 8b 0d ?? ?? ?? ?? 83 c1 62 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 88 4a 0e a1 ?? ?? ?? ?? 83 c0 36 8b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 88 41 0f 8b 15 ?? ?? ?? ?? 83 c2 61 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 88 50 10 8b 0d ?? ?? ?? ?? 83 c1 38 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 88 4a 11 a1 ?? ?? ?? ?? 83 c0 30 8b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 88 41 12 8b 15 ?? ?? ?? ?? 83 c2 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PC_2147726926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PC!bit"
        threat_id = "2147726926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "KLONE_X64-PC" ascii //weight: 1
        $x_1_2 = "C:\\take_screenshot.ps1" wide //weight: 1
        $x_1_3 = {5c 00 65 00 6d 00 61 00 69 00 6c 00 2e 00 68 00 74 00 6d 00 00 00 43 00 3a 00 5c 00 31 00 32 00 33 00 5c 00 65 00 6d 00 61 00 69 00 6c 00 2e 00 64 00 6f 00 63 00}  //weight: 1, accuracy: High
        $x_1_4 = "C:\\a\\foobar.bmp" wide //weight: 1
        $x_1_5 = {31 d2 f7 f1 8b 0d ?? ?? ?? ?? 8a 1c 11 8b 4d ?? 8b 55 ?? 8a 3c 11 28 df 88 3c 11 81 c2 ff 00 00 00 8b 75 ?? 39 f2 89 55 ?? 72}  //weight: 1, accuracy: Low
        $x_1_6 = {89 f1 01 c1 83 c1 08 8b 01 8b 4d ?? c6 01 ?? 8b 4d ?? 29 cf 8b 4d ?? 01 f9 01 d9 8b 7d ?? 89 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PB_2147727416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PB"
        threat_id = "2147727416"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 8b ff 01 05 ?? ?? ?? ?? 8b ff 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AE_2147727932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AE"
        threat_id = "2147727932"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "face\\{aa5b6a80-b834-11d0-932f-00a0c90dcaa9}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AF_2147727933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AF"
        threat_id = "2147727933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 08 6a ?? 6a ?? e8 ?? ?? ?? ?? 83 c4 08 6a ?? 6a ?? e8 ?? ?? ?? ?? 83 c4 08 6a ?? 6a ?? e8 ?? ?? ?? ?? 83 c4 08 6a ?? 6a ?? e8 ?? ?? ?? ?? 83 c4 08 6a ?? 6a ?? e8 ?? ?? ?? ?? 83 c4 08 6a ?? 6a ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 04 6a ?? e8 ?? ?? ?? ?? 83 c4 04 6a ?? e8 ?? ?? ?? ?? 83 c4 04 6a ?? e8 ?? ?? ?? ?? 83 c4 04 6a ?? e8 ?? ?? ?? ?? 83 c4 04 6a ?? e8 ?? ?? ?? ?? 83 c4 04 6a ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_AN_2147728172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AN"
        threat_id = "2147728172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hegwwerherher@@!.pdb" ascii //weight: 1
        $x_1_2 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 77 00 66 00 77 00 2e 00 66 00 77 00 66 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AS_2147728497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AS"
        threat_id = "2147728497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "3MsiDataW.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_2147728976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet!MTB"
        threat_id = "2147728976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 51 64 a1 30 00 00 00 89 45 fc 8b 45 fc 8b e5 5d}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 56 57 8b 75 08 33 ff 33 c0 fc ac 84 c0 74 07 c1 cf 0d 03 f8 eb f4 8b c7 5f 5e 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_V_2147729264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.V!MTB"
        threat_id = "2147729264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 44 8c 0c 8b f2 8b 54 b4 0c 89 54 8c 0c 0f b6 d0 89 54 b4 0c 8b 44 8c 0c 03 c2 99 f7 fd 0f b6 44 94 0c 30 44 1f ff 3b bc 24 94 07 00 00 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_V_2147729264_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.V!MTB"
        threat_id = "2147729264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 51 01 8d 49 00 8a 01 41 84 c0 75 f9 2b ca 8b c6 33 d2 f7 f1 46 8a 82 ?? ?? ?? ?? 30 44 3e ff 3b f3 72 d7 8d 45 f8 50 6a 40 53 57 ff 15 ?? ?? ?? ?? 8b 45 b0 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AO_2147729590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AO"
        threat_id = "2147729590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\does\\swim\\have\\Slow\\we\\loneappear.pdb" ascii //weight: 1
        $x_1_2 = "c:\\broad\\Chief\\light\\steel\\Ten\\Mark\\pastPerhaps.pdb" ascii //weight: 1
        $x_1_3 = "c:\\Wife\\Substance\\job\\moon\\work\\Post\\ironProcess.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_AD_2147730059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AD!MTB"
        threat_id = "2147730059"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 f6 2b 30 f7 de 83 c0 ?? 83 ee ?? 01 fe 83 c6 ?? 8d 3e c7 01 00 00 00 00 09 31 83 c1 04 83 c3 04 81 fb ?? ?? ?? ?? 75 ?? 59 ff 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AD_2147730059_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AD!MTB"
        threat_id = "2147730059"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 24 0a 8b 54 24 ?? 8a 5c 24 ?? c7 44 24 ?? 00 00 00 00 c7 44 24 ?? 00 00 00 00 01 ce b7 31 28 df 30 f8 00 c4}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 04 8a 4c 24 ?? 88 08 8d 65 ?? 5e 5f 5b 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AD_2147730059_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AD!MTB"
        threat_id = "2147730059"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 f8 81 75 f8 ?? ?? ?? ?? 8a 4d f8 8b 75 fc c7 45 f8}  //weight: 1, accuracy: Low
        $x_1_2 = {89 45 f8 c1 65 f8 04 81 75 f8 ?? ?? ?? ?? 8a 4d f8 8b 55 fc 0f be 03 89 45 fc}  //weight: 1, accuracy: Low
        $x_1_3 = {01 75 fc d3 e2 01 55 fc}  //weight: 1, accuracy: High
        $x_1_4 = {29 7d fc 43 80 3b 00 75 a4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AD_2147730059_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AD!MTB"
        threat_id = "2147730059"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 72 74 75 75 6c 41 6c 6c 6f 63 ?? ?? ?? 72 6e 65 6c 33 32 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $n_1_2 = {76 69 72 74 75 61 6c 41 6c 6c 6f 63 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c}  //weight: -1, accuracy: High
        $x_1_3 = {ff 36 5f 83 ee fc 83 c7 ?? 01 cf 83 ef ?? 29 c9 49 21 f9 c6 03 00 09 3b 83 c3 04 83 c2 04 81 fa ?? ?? ?? ?? 75 ?? 5b ff 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff e3}  //weight: 1, accuracy: Low
        $x_1_4 = {ff 32 58 83 c2 04 83 c0 de 01 c8 83 c0 ?? 50 59 c6 03 00 09 03 83 c3 ?? 83 c6 ?? 83 fe ?? 75 ?? 5b ff 35 ?? ?? ?? ?? ff d3}  //weight: 1, accuracy: Low
        $x_1_5 = {ff 36 5f 83 ee fc 83 c7 de 01 cf 83 ef ?? 29 c9 49 21 f9 c6 03 00 09 3b 83 c3 04 83 c2 04 81 fa ?? ?? ?? ?? 75 ?? 5b ff 35 ?? ?? ?? ?? ff d3}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 33 83 c3 04 83 ee 22 8d 34 06 83 c6 ff 29 c0 29 f0 f7 d8 c6 07 00 01 37 83 c7 04 83 c1 04 8d 35 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 56 c3}  //weight: 1, accuracy: Low
        $x_1_7 = {31 db 2b 1a f7 db 83 ea fc 83 c3 de 8d 1c 33 83 eb 01 8d 33 c6 07 00 01 1f 83 ef fc 83 c1 fc 83 f9 00 75 ?? 5f ff 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? 57}  //weight: 1, accuracy: Low
        $x_1_8 = {29 d2 2b 16 f7 da 83 ee fc 83 ea 22 8d 14 1a 8d 52 ff 89 d3 c6 07 00 09 17 83 c7 04 83 c1 fc 8d 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 52}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_AU_2147730601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AU"
        threat_id = "2147730601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 16 8d 49 08 33 55 08 8d 76 04 0f b6 c2 47 66 89 41 f8 8b c2 c1 e8 08 0f b6 c0 66 89 41 fa c1 ea 10 0f b6 c2 66 89 41 fc c1 ea 08 0f b6 c2 66 89 41 fe 3b fb 72 c9}  //weight: 2, accuracy: High
        $x_2_2 = {8b 16 8d 49 04 [0-6] 8d 76 04 88 51 fc 8b c2 c1 e8 08 47 c1 ea 10 88 41 fd 88 51 fe c1 ea 08 88 51 ff 3b fb 72}  //weight: 2, accuracy: Low
        $x_1_3 = {66 83 38 5c 74 0b 83 c0 02 66 83 38 00 75 f1 eb 06 33 c9 66 89 48 02 6a 00}  //weight: 1, accuracy: High
        $x_1_4 = {83 c4 04 33 c9 39 4d 14 8b f0 0f 45 ce 6a 00 68 00 c3 4c 84 6a 00 6a 00 6a 00 [0-3] 51 57 ff 15 ?? ?? ?? ?? 56 6a 00 8b f8 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AU_2147730601_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AU"
        threat_id = "2147730601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 a8 50 6a 00 6a 00 ff 75 08 6a 00 6a 00 6a 00 6a 00 56 ff 15 ?? ?? ?? ?? 85 c0 74 36 8b 45 0c 85 c0 74 13 f3 0f 6f 45 f0 f3 0f 7f 00 b8 01 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 75 f0 ff 15 ?? ?? ?? ?? ff 75 f4 ff 15 ?? ?? ?? ?? b8 01 00 00 00 5e 8b e5 5d}  //weight: 1, accuracy: Low
        $x_1_3 = {74 05 e8 72 dd ff ff 6a 00 ff 15 ?? ?? ?? ?? 8b e5 5d}  //weight: 1, accuracy: Low
        $x_1_4 = {68 04 01 00 00 68 ?? ?? ?? ?? 6a 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_5 = {74 1d 8d a4 24 00 00 00 00 80 f9 2c 74 11 66 0f be c9 40 66 89 0e 83 c6 02 8a 08 84 c9 75 ea e9}  //weight: 1, accuracy: High
        $x_1_6 = {c7 85 7c fa ff ff 6b 27 76 ce c7 85 80 fa ff ff db a1 63 b9 c7 85 84 fa ff ff 7a 02 e2 97}  //weight: 1, accuracy: High
        $x_1_7 = {c7 45 84 2e b2 c9 70 c7 45 88 42 45 ff e3}  //weight: 1, accuracy: High
        $x_1_8 = {c7 85 e0 f9 ff ff e5 c3 13 37 c7 85 e4 f9 ff ff c2 8e fd 06 c7 85 e8 f9 ff ff 6d 26 8e 9c}  //weight: 1, accuracy: High
        $x_1_9 = {74 58 49 48 5c 68 07 45 88 be ff 26 9b}  //weight: 1, accuracy: High
        $x_1_10 = {c7 45 f8 e6 61 c7 b9 c7 45 fc b1 7a c0 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Emotet_AU_2147730602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AU!!Emotet.gen!B"
        threat_id = "2147730602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "Emotet: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 a8 50 6a 00 6a 00 ff 75 08 6a 00 6a 00 6a 00 6a 00 56 ff 15 ?? ?? ?? ?? 85 c0 74 36 8b 45 0c 85 c0 74 13 f3 0f 6f 45 f0 f3 0f 7f 00 b8 01 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 75 f0 ff 15 ?? ?? ?? ?? ff 75 f4 ff 15 ?? ?? ?? ?? b8 01 00 00 00 5e 8b e5 5d}  //weight: 1, accuracy: Low
        $x_1_3 = {74 05 e8 72 dd ff ff 6a 00 ff 15 ?? ?? ?? ?? 8b e5 5d}  //weight: 1, accuracy: Low
        $x_1_4 = {68 04 01 00 00 68 ?? ?? ?? ?? 6a 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_5 = {74 1d 8d a4 24 00 00 00 00 80 f9 2c 74 11 66 0f be c9 40 66 89 0e 83 c6 02 8a 08 84 c9 75 ea e9}  //weight: 1, accuracy: High
        $x_1_6 = {c7 85 7c fa ff ff 6b 27 76 ce c7 85 80 fa ff ff db a1 63 b9 c7 85 84 fa ff ff 7a 02 e2 97}  //weight: 1, accuracy: High
        $x_1_7 = {c7 45 84 2e b2 c9 70 c7 45 88 42 45 ff e3}  //weight: 1, accuracy: High
        $x_1_8 = {c7 85 e0 f9 ff ff e5 c3 13 37 c7 85 e4 f9 ff ff c2 8e fd 06 c7 85 e8 f9 ff ff 6d 26 8e 9c}  //weight: 1, accuracy: High
        $x_1_9 = {74 58 49 48 5c 68 07 45 88 be ff 26 9b}  //weight: 1, accuracy: High
        $x_1_10 = {c7 45 f8 e6 61 c7 b9 c7 45 fc b1 7a c0 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Emotet_PS_2147730664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PS"
        threat_id = "2147730664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {31 c9 41 83 ec 04 c1 e1 05 81 f9 98 00 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {81 cb 81 3a 00 00 43 46 81 ce 01 40 00 40}  //weight: 10, accuracy: High
        $x_10_3 = {81 f1 b1 c2 ef 3c}  //weight: 10, accuracy: High
        $x_10_4 = {68 91 7f 09 00 68 de 7e d9 00}  //weight: 10, accuracy: High
        $x_10_5 = {68 9f c3 79 00}  //weight: 10, accuracy: High
        $x_10_6 = {68 ee fb 58 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Emotet_BD_2147730882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BD"
        threat_id = "2147730882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=qc5v4234v5\\\\23v45234\\\\22345v2345.7Ru.pdb" ascii //weight: 1
        $x_1_2 = "ciTfDCxMQU0a5/DDEyGwn8ta.z4.pdb" ascii //weight: 1
        $x_1_3 = "7laIR+|.XJ5aA0aa.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_BD_2147730882_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BD"
        threat_id = "2147730882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Branchsupermanmads2015zchelseae" wide //weight: 1
        $x_1_2 = "outChrome8UChromelU" wide //weight: 1
        $x_1_3 = "browsers.62pbasis.856Junder7O" ascii //weight: 1
        $x_1_4 = "offlinecompletelyBetaK4implementedfor" wide //weight: 1
        $x_1_5 = "exploitsChromet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BE_2147730883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BE"
        threat_id = "2147730883"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\rel\\iMS-srvreg56.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BE_2147730883_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BE"
        threat_id = "2147730883"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Chen32.pdb" ascii //weight: 10
        $x_10_2 = "m3KHLMcF.pdb" ascii //weight: 10
        $x_10_3 = "rSVz/f9=GI0.pdb" ascii //weight: 10
        $x_10_4 = "@dMlE|vKpq.pdb" ascii //weight: 10
        $x_10_5 = "SKRFM.pdb" ascii //weight: 10
        $x_1_6 = "forQisalex" ascii //weight: 1
        $x_1_7 = "jessicaqGooglejCD" ascii //weight: 1
        $x_1_8 = "somewhatmGChromeH" wide //weight: 1
        $x_1_9 = "lifebrowser.wasThecdm" wide //weight: 1
        $x_1_10 = "find first big value" wide //weight: 1
        $x_1_11 = "LvEwEN teLgdy Bt WVVHLU ltHeU" wide //weight: 1
        $x_1_12 = "nmcogame.dll" wide //weight: 1
        $x_1_13 = "NexonMessenger Game Service" wide //weight: 1
        $x_1_14 = "Namespc2.dll" wide //weight: 1
        $x_1_15 = "Logitech QuickCam" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_BL_2147730889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BL"
        threat_id = "2147730889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uniqueamsurge" wide //weight: 1
        $x_1_2 = "GoogleInscore.67dafter" wide //weight: 1
        $x_1_3 = "jaguar8ChromeHjudgeChrome" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BM_2147730890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BM"
        threat_id = "2147730890"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ZbsuitesufferingOtests" wide //weight: 1
        $x_1_2 = "Vcrashclassuinformation55it" wide //weight: 1
        $x_1_3 = "theTermsrMainwebChrome" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BX_2147730891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BX"
        threat_id = "2147730891"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "JERJWHETW@##HREjwr.Pdb" ascii //weight: 2
        $x_1_2 = {ff ff 74 13 09 d0 83 c8 01 83 c1 04 83 f8 00 8b 0d ?? ?? ?? ?? ff e1 31 c0 89 45 fc c3 31 c0 31 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BO_2147730892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BO"
        threat_id = "2147730892"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "he#@1.Pdb" ascii //weight: 1
        $x_3_2 = {8b 44 24 18 89 c1 83 e0 ?? 8a ?? ?? ?? ?? ?? c7 44 24 ?? ?? ?? ?? ?? c7 44 24 ?? ?? ?? ?? ?? 8b 44 24 ?? 8a 34 08 28 d6 8b 74 24 ?? 88 34 0e 83 c1 ?? 89 4c 24 ?? 8b 7c 24 ?? 39 f9 74}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BP_2147730893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BP"
        threat_id = "2147730893"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "he#@1.Pdb" ascii //weight: 3
        $x_1_2 = "S Corpora" wide //weight: 1
        $x_1_3 = "SQLCEOLED" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_BQ_2147730894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BQ"
        threat_id = "2147730894"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "heerhWHW#@1wHJnERbRW.Pdb" ascii //weight: 3
        $x_3_2 = "EWH#@1wHJnERbRW.Pdb" ascii //weight: 3
        $x_2_3 = {6e 00 69 00 37 00 3d 00 38 00 68 00 4c 00 4f 00 36 00 6f}  //weight: 2, accuracy: High
        $x_1_4 = "S Corpora" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_BR_2147730895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BR"
        threat_id = "2147730895"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "r.4YM4qhCz5DavnCoPhjjx.pdb" ascii //weight: 3
        $x_3_2 = "kO@fbLLEFmk2I_M.pdb" ascii //weight: 3
        $x_1_3 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 6d 00 69 00 63 00 72 00 6f 00 2e 00 65 00 78 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_BS_2147730896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BS"
        threat_id = "2147730896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "Pb730.pdb" ascii //weight: 4
        $x_1_2 = "fHykYt UzpnPr XUCSp NOjgDAbYvm UNZD AA" wide //weight: 1
        $x_1_3 = "Yk fn on NUcwblgc Ahwm Jzb" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BS_2147730896_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BS"
        threat_id = "2147730896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "rSVz/f9=GI0.pdb" ascii //weight: 1
        $x_1_2 = {89 c1 83 e1 ?? 83 f8 ?? 0f 42 c8 8b ?? ?? 39 d1 0f 97 c3 83 f9 ?? 0f 97 c7 08 fb f6 c3 ?? 89 ?? ?? 89 ?? ?? 75 [0-2] 8b ?? ?? 8a ?? ?? ?? ?? ?? ?? 8b ?? ?? 8b ?? ?? 8a 2c 32 28 cd 8b ?? ?? 88 2c 37 83 c6 ?? 8b 5d ?? 39 de 89 75 ?? 72}  //weight: 1, accuracy: Low
        $x_1_3 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 53 00 6f 00 66 00 74 00 70 00 75 00 62}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BS_2147730896_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BS"
        threat_id = "2147730896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "breHERVWrnEGREb stop zrfHffsZGeH ZVgltdnxH 837836" wide //weight: 1
        $x_1_2 = "CKv.awEVWehWRNWR JZ(ky)WEF" wide //weight: 1
        $x_1_3 = "ni7=8hLO6o" wide //weight: 1
        $x_1_4 = "WhjrkehLkpe;rltjhpow;elkrjjklWEKL#.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BN_2147730897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BN"
        threat_id = "2147730897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "r.4YM4qhCz5DavnCoPhjjx.pdb" ascii //weight: 1
        $x_1_2 = "breHERVWrnEGREb stop zrfHffsZGeH ZVgltdnxH 837836" wide //weight: 1
        $x_1_3 = "S Corpora" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BT_2147730898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BT"
        threat_id = "2147730898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "Pb730.pdb" ascii //weight: 4
        $x_4_2 = "sNQ.pdb" ascii //weight: 4
        $x_2_3 = "ttbw Ga Pr NUcwblgc Ahwm Jzb" wide //weight: 2
        $x_2_4 = "fHykYt UzpnPr XUCSp NOjgDAbYvm UNZD AA" wide //weight: 2
        $x_1_5 = "IDI_DUKE_ICON" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_BT_2147730898_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BT"
        threat_id = "2147730898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "breHERVWrnEGREb stop zrfHffsZGeH ZVgltdnxH 837836" wide //weight: 1
        $x_1_2 = "CKv.awEVWehWRNWR JZ(ky)WEF" wide //weight: 1
        $x_1_3 = "ni7=8hLO6o" wide //weight: 1
        $x_1_4 = "+9!myD0iY5!ussu_svXy5bni8J8CU.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BU_2147730899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BU"
        threat_id = "2147730899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lehAh.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BU_2147730899_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BU"
        threat_id = "2147730899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "@dMlE|vKpq.pdb" ascii //weight: 1
        $x_1_2 = "rSVz/f9=GI0.pdb" ascii //weight: 1
        $x_3_3 = "keybd_event" ascii //weight: 3
        $x_2_4 = {8b 45 e4 89 c1 83 e1 07 83 f8 08 0f 42 c8 8b 55 f0 39 d1 0f 97 c3 83 f9 08 0f 97 c7 08 fb f6 c3 01 89 45 e0 89 4d dc 75 ?? 8b 45 ec 8b 4d e0 8a 14 08 8b 75 dc 2a 14 35 9e 32 40 00 8b 7d e8 88 14 0f 83 c1 01 8b 5d f0 39 d9 89 4d e4 72 b1}  //weight: 2, accuracy: Low
        $x_2_5 = {29 fa 89 45 ?? 89 c8 31 ff 89 55 ?? 89 fa 8b 7d ?? f7 f7 89 cb 21 f3 8b 75 ?? 01 ce 8b 7d ?? 83 ff 02 0f 47 da 8a 14 1d ?? ?? ?? ?? 8b 5d ?? 8a 34 0b 28 d6 8b 7d ?? 88 34 0f 83 c1 33 8b 7d ?? 39 f9 89 75 ?? 89 4d ?? 72 a0 e9 56 ff ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_BV_2147730900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BV"
        threat_id = "2147730900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "he#@1.Pdb" ascii //weight: 1
        $x_1_2 = "YUQ9F*miOq" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BW_2147730901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BW"
        threat_id = "2147730901"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@g-e3e_2qalAN+/PaKV/J.pdb" ascii //weight: 1
        $x_1_2 = "Debugger" wide //weight: 1
        $x_1_3 = "A od BRWQEWJ jq Mywmy Yb Q" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BG_2147730902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BG"
        threat_id = "2147730902"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SrQUFmG.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BH_2147730903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BH"
        threat_id = "2147730903"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 3c 8a 0c 05 ?? ?? ?? ?? 8b 54 24 20 81 f2 ?? ?? ?? ?? 8a 2c 05 ?? ?? ?? ?? 28 cd 89 94 24 9c 00 00 00 88 6c 04 48 83 c0 01 89 44 24 3c 83 f8 0e}  //weight: 1, accuracy: Low
        $x_1_2 = {88 54 24 0b 89 f2 8b 74 24 10 f7 f6 8b 74 24 20 89 4c 24 04 8a 0c 3e 8b 7c 24 0c 8a 2c 17 28 e9 8a 54 24 0b 80 c2 01 8b 74 24 1c 88 0c 1e 8b 5c 24 38 30 ea 8b 8c 24 ?? ?? ?? ?? 8b 74 24 28 d3 ee 89 b4 24 ?? ?? ?? ?? 88 13 8b 74 24 04 03 74 24 30 89 74 24 2c 8b 5c 24 28 39 de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BI_2147730904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BI"
        threat_id = "2147730904"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 2c 8b 8c 24 ?? ?? ?? ?? 81 f1 19 ff a4 32 89 c2 21 ca 8a 1c 05 ?? ?? ?? ?? 2a 1c 15 ?? ?? ?? ?? 8b 8c 24 ?? ?? ?? ?? 81 c1 eb 00 5b cd 88 5c 04 3c 01 c8 89 44 24 2c 83 f8 18}  //weight: 1, accuracy: Low
        $x_1_2 = {31 c9 89 54 24 10 89 ca 8b 4c 24 14 f7 f1 8a 3c 16 28 fb 8b 54 24 10 81 e2 ff 00 00 00 8a 4c 14 48 80 c1 01 8b 74 24 1c 88 1c 3e 30 f9 88 4c 14 48}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BJ_2147730905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BJ"
        threat_id = "2147730905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 14 8a 0c 05 ?? ?? ?? ?? 2a 0c 05 ?? ?? ?? ?? 88 4c 04 58 8b 94 24 84 00 00 00 81 c2 63 d8 8f f1 8b 74 24 30 69 fe f4 05 3f 31 89 bc 24 88 00 00 00 83 c0 01 39 d0 89 44 24 14}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 1c 32 89 c2 88 d7 89 0c 24 88 f9 8b 14 24 0f a5 c2 88 f9 d3 e0 31 f6 f6 c7 20 0f 45 d0 0f 45 c6 8b 74 24 14 8b 7c 24 0c 8a 0c 37 8b bc 24 ?? ?? ?? ?? 81 c7 d3 c4 10 a2 28 d9 89 94 24 ?? ?? ?? ?? 89 84 24 ?? ?? ?? ?? 8b 44 24 08 88 0c 30}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 44 24 30 8a 0c 05 ?? ?? ?? ?? 2a 0c 05 ?? ?? ?? ?? 88 8c 04 88 00 00 00 8b 54 24 14 89 94 24 b4 00 00 00 83 c0 01 89 44 24 30 83 f8 0e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BK_2147730906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BK"
        threat_id = "2147730906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 d7 8d b4 0a 51 ff ff ff 81 fe 23 0b 00 00 72 0c 8d 44 0a 05 c7 44 24 1c 00 00 00 00 33 ed 8d 71 e4 2b f0 1b 6c 24 1c 03 d3 81 fa b5 00 00 00 89 35 08 90 42 00 89 2d 0c 90 42 00 75 0f 8b 15 04 90 42 00 2b d0 8d 54 51 f4 0f b7 fa 0f b7 d7 03 d2 8d b2 51 ff ff ff 81 fe 23 0b 00 00 7c 08 8d 42 05 99 89 54 24 1c 0f af cf 8b 54 24 10 8b 1a 03 c8 0f b7 f9 8b 4c 24 20 01 0d 10 90 42 00}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 f7 b9 00 00 00 00 11 0d 14 90 42 00 8b ce 2b 0d 04 90 42 00 83 c1 0f 8d ac 0e 51 ff ff ff 81 fd 23 0b 00 00 72 14 8d 74 0e 05 89 35 08 90 42 00 c7 05 0c 90 42 00 00 00 00 00 8b f1 0f af f7 8d 74 06 01 0f af f1 0f b7 fe 0f b7 f7 81 c3 c0 9b de 01 8d ac 0e 51 ff ff ff 81 fd 23 0b 00 00 89 1a 72 14 8d 6c 0e 05 89 2d 08 90 42 00 c7 05 0c 90 42 00 00 00 00 00 0f af 35 10 90 42 00 6b f6 f3 83 c2 04 03 ce 83 6c 24 14 01 89 54 24 10 0f 85 e8 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BF_2147730909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BF"
        threat_id = "2147730909"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XrfZPp2C.pdb" ascii //weight: 1
        $x_1_2 = "LQYutoXRJpQBI-zyVe.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_BF_2147730909_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BF"
        threat_id = "2147730909"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "t_D!Ay=VaDyaKDa.pdb" ascii //weight: 1
        $x_1_2 = "erjRWJERJketkjQEWYHJ@#.Pdb" ascii //weight: 1
        $x_1_3 = "ynmNa1OjKdUie.pdb" ascii //weight: 1
        $x_1_4 = "JOe|OBzjATck#psb/.pdb" ascii //weight: 1
        $x_1_5 = "hkhjggh.Pdb" ascii //weight: 1
        $x_1_6 = "CryARr.pdb" ascii //weight: 1
        $x_1_7 = "zYAamTGB2rfW!Cp+aR.pdb" ascii //weight: 1
        $x_1_8 = "ewhwwherGW.Pdb" ascii //weight: 1
        $x_1_9 = "hewrjkrkter#whrje@wg.Pdb" ascii //weight: 1
        $x_1_10 = "uigjhghio.pdb" ascii //weight: 1
        $x_1_11 = "QPK+LbZjb*4KV@InYQ*.pdb" ascii //weight: 1
        $x_1_12 = "odubqa.pdb" ascii //weight: 1
        $x_1_13 = "7h4qMQ1edvEOY+wQIOdVR_v.pdb" ascii //weight: 1
        $x_1_14 = "3Vv@p=i8qg.ylQJxx!l.pdb" ascii //weight: 1
        $x_1_15 = "HXe5+GENxShM.pdb" ascii //weight: 1
        $x_1_16 = "2ezUVGr!PtB.pdb" ascii //weight: 1
        $x_1_17 = "iwJL##$@#*$^#%@!^$.pdb" ascii //weight: 1
        $x_1_18 = "eTiq_WaEN__y9F89zLukjmM.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_BF_2147730909_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BF"
        threat_id = "2147730909"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 c4 58 c6 86 9f 4c 68 c6 f4 4c 68 08 c5 28 c6 8f 0c 68 c6 4c 68 c6 08 c5 78 c6 8f 4c 68 c5}  //weight: 1, accuracy: High
        $x_1_2 = {00 49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 [0-2] 00 65 00 63 00 75 00 72 00 69 00 74 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {00 43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 53 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "hWEHW#@HJERKJERJER^$.Pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Emotet_P_2147730952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.P!!Emotet.gen!B"
        threat_id = "2147730952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "Emotet: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_40_1 = {54 89 e0 83 e8 10 31 c9 89 1d ?? ?? ?? ?? 01 d8 83 c8 01 83 c1 04 83 f8 00 74 24 8f 05 ?? ?? ?? ?? 01 0d ?? ?? ?? ?? 8f 05 ?? ?? ?? ?? 83 f9 00 0f 85 ?? ?? ?? ?? 85 c0 74 05 b8 ff 00 00 00}  //weight: 40, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PS_2147730953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PS!!Emotet.gen!B"
        threat_id = "2147730953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "Emotet: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {31 c9 41 83 ec 04 c1 e1 05 81 f9 98 00 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {81 cb 81 3a 00 00 43 46 81 ce 01 40 00 40}  //weight: 10, accuracy: High
        $x_10_3 = {81 f1 b1 c2 ef 3c}  //weight: 10, accuracy: High
        $x_10_4 = {68 91 7f 09 00 68 de 7e d9 00}  //weight: 10, accuracy: High
        $x_10_5 = {68 9f c3 79 00}  //weight: 10, accuracy: High
        $x_10_6 = {68 ee fb 58 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Emotet_M_2147730954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.M!!Emotet.gen!B"
        threat_id = "2147730954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "Emotet: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 e7 03 83 e7 18 89 4d d4 89 f9 d3 e6 31 c6 8b 45 ec 8a 0c 02 8b 55 f0 88 0a 8b 7d d4 83 c7 01}  //weight: 10, accuracy: High
        $x_10_2 = {15 18 00 00 00 31 ?? 8b ?? 30 8b ?? 0c}  //weight: 10, accuracy: Low
        $x_10_3 = {74 0a a1 18 30 ?? 00 ff d0}  //weight: 10, accuracy: Low
        $x_10_4 = {8b 30 8b 78 04 8b 58 08 8b 68 0c 8b 60 10 8b 40 14 ff e0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AA_2147730959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AA"
        threat_id = "2147730959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 04 8a 0c 05 ?? ?? ?? ?? 8a 14 05 ?? ?? ?? ?? 28 ca 88 54 04 64 83 c0 01 83 f8 0e 89 44 24 04}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 18 8a 0c 05 ?? ?? ?? ?? 8a 14 05 ?? ?? ?? ?? 28 ca 88 54 04 28 83 c0 01 89 44 24 18 83 f8 0e}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 44 24 2c 8a 0c 05 ?? ?? ?? ?? 2a 0c 05 ?? ?? ?? ?? 88 4c 04 40 83 c0 01 89 44 24 34 8b 44 24 34 8b 54 24 34 89 54 24 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Emotet_AC_2147730960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AC"
        threat_id = "2147730960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 ec 8b 4d e0 8a 14 08 8b 75 dc 2a 14 35 ?? ?? ?? ?? 8b 7d e8 88 14 0f 83 c1 01 8b 5d f0 39 d9 89 4d e4 73 d2}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 d0 8b 4d d4 ba 32 00 00 00 89 45 cc 89 c8 31 f6 89 55 c8 89 f2 8b 75 c8 f7 f6 89 cf 83 e7 03 8b 5d cc 83 fb 02 0f 47 fa 8a 14 3d ?? ?? ?? ?? 8b 7d e8 8a 34 0f 28 d6 01 cb 8b 75 e4 88 34 0e 83 c1 33 8b 75 ec 39 f1 89 4d d4 89 5d d0 72 af}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AD_2147730961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AD"
        threat_id = "2147730961"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pexploitswasOSJtoThe" ascii //weight: 1
        $x_1_2 = "thepreviouslymemoryWebKitChromeY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AD_2147730961_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AD"
        threat_id = "2147730961"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ff 8b ca a3 ?? ?? ?? ?? 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 31 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 8b ff 01 05 ?? ?? ?? ?? 8b ff 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11 5f 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AD_2147730961_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AD"
        threat_id = "2147730961"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 11 2a 44 24 4b 8a 64 24 2b 30 c4 00 e2 8b 4c 24 0c 8b 74 24 14 88 14 31}  //weight: 1, accuracy: High
        $x_1_2 = {8a 75 cb 80 c6 73 8b 45 e4 8b 4d cc 02 34 08 28 d6 8b 75 e0 88 34 0e 83 c1 3e 8b 7d e8 39 f9 8b 5d c4 89 5d d0 89 4d d4 72 ae}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 e4 8b 4d f4 81 c1 7a 04 8e b7 89 c2 21 ca 8b 4d e8 89 0c 24 8b 75 ec 89 74 24 04 89 44 24 08 0f b6 14 15 ?? ?? ?? ?? 89 54 24 0c 89 45 e0 e8 d2 0b 00 00 8b 45 e0 83 c0 01 8b 4d f0 39 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Emotet_BZ_2147730969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BZ"
        threat_id = "2147730969"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$.Pdb" ascii //weight: 1
        $x_1_2 = "hWEHW#@HJERKJERJER" ascii //weight: 1
        $x_1_3 = "WerMgr" wide //weight: 1
        $x_1_4 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 ae 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 ae 00 20 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 20 00 53 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_X_2147730999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.X"
        threat_id = "2147730999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 ad ff ff ff 83 f9 02 89 45 fc 74 10 81 fc 1f 01 00 00 e8 9a ff ff ff e8 ?? ?? ff ff 31 c0 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 ad ff ff ff 83 f9 02 89 45 fc 74 10 81 fc 1f 01 00 00 e8 9a ff ff ff e8 ?? ?? ff ff 31 c0 c3 31 c0 31 c0 89 45 f8 55 89 e5}  //weight: 1, accuracy: Low
        $x_1_3 = {4d 00 75 00 73 00 69 00 63 00 6d 00 61 00 74 00 63 00 68 00 ae 00 2c 00 20 00 49 00 6e 00 63 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_P4_2147731044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.P4"
        threat_id = "2147731044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 52 53 44 53}  //weight: 5, accuracy: High
        $x_5_2 = {00 31 2e 70 64 62 00}  //weight: 5, accuracy: High
        $x_10_3 = "UPRkWonL/0Jb13NDYSa" ascii //weight: 10
        $x_10_4 = "9W1jZbeihy&xB^tUlmF" ascii //weight: 10
        $x_10_5 = {89 3d 64 f7 46 00 c7 05 58 f7 46 00 12 00 00 00 c7 05 68 f7 46 00 00 00 00 00 c7 05 60 f7 46 00 00 00 00 00 89 35 5c f7 46 00 01 25 58 f7 46 00 01 2d 68 f7 46 00 01 1d 60 f7 46 00 83 2d 58 f7 46 00 0e c3}  //weight: 10, accuracy: High
        $x_10_6 = {89 3d c4 df 46 00 c7 05 b8 df 46 00 12 00 00 00 c7 05 c8 df 46 00 00 00 00 00 c7 05 c0 df 46 00 00 00 00 00 89 35 bc df 46 00 01 25 b8 df 46 00 01 2d c8 df 46 00 01 1d c0 df 46 00 83 2d b8 df 46 00 0e c3}  //weight: 10, accuracy: High
        $x_10_7 = {89 3d 34 fb 46 00 c7 05 28 fb 46 00 12 00 00 00 c7 05 38 fb 46 00 00 00 00 00 c7 05 30 fb 46 00 00 00 00 00 89 35 2c fb 46 00 01 25 28 fb 46 00 01 2d 38 fb 46 00 01 1d 30 fb 46 00 83 2d 28 fb 46 00 0e c3}  //weight: 10, accuracy: High
        $x_10_8 = {0c 00 00 00 14 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 f0 3f}  //weight: 10, accuracy: Low
        $x_10_9 = {8b 44 24 14 f2 0f 2a c0 48 50}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_5_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_CA_2147731158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CA"
        threat_id = "2147731158"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DemoShield" wide //weight: 2
        $x_2_2 = "gz3Cmostcompletely" wide //weight: 2
        $x_4_3 = "PSXPSXPSXPSXPSXPSXfffff" ascii //weight: 4
        $x_2_4 = "macro.exe" wide //weight: 2
        $x_2_5 = "wereniconaszFlash" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_CB_2147731159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CB"
        threat_id = "2147731159"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5d c2 0c 00 31 35 ?? ?? 45 00 31 05 ?? ?? 45 00 e8 ?? ?? ff ff 89 45 fc 55 89 e5}  //weight: 5, accuracy: Low
        $x_1_2 = "CryptDuplicateKey" ascii //weight: 1
        $x_1_3 = "FlushProcessWriteBuffers" ascii //weight: 1
        $x_1_4 = "esentutl.exe" wide //weight: 1
        $x_1_5 = "DemoShield" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_CD_2147731168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CD"
        threat_id = "2147731168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NjhZWN_c34e" ascii //weight: 1
        $x_1_2 = "e<#@M=YEecd" wide //weight: 1
        $x_1_3 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 56 00 62 00 6f 00 78 00 20 00 54 00 72 00 69 00 61 00 6c 00 20 00 43 00 6c 00 69 00 65 00 6e 00 74 00 20 00 44 00 4c 00 4c}  //weight: 1, accuracy: High
        $x_1_4 = "iFnK2.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CD_2147731168_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CD"
        threat_id = "2147731168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CzjdEGy5WJhOuuMYwriT3_p6At+.pdb" ascii //weight: 1
        $x_1_2 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 73 00 61 00 6e 00 6e 00 65 00 2e 00 65 00 78 00 65}  //weight: 1, accuracy: High
        $x_1_3 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 4c 00 65 00 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CF_2147731179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CF"
        threat_id = "2147731179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "odubqa.pdb" ascii //weight: 2
        $x_2_2 = "Troneton.pdb" ascii //weight: 2
        $x_1_3 = "NjhZWN_c34e" ascii //weight: 1
        $x_1_4 = "ODBC (3.0) driver for DBase" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_CF_2147731179_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CF"
        threat_id = "2147731179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {55 54 b9 04 00 00 00 89 1d ?? ?? 40 00 83 f9 03 74 20 58 01 c8 8f 05 ?? ?? 40 00 a3 ?? ?? 40 00 39 e0 0f 84}  //weight: 7, accuracy: Low
        $x_8_2 = {83 f8 04 74 03 89 45 fc c3 5a 01 ca 85 c0 89 15 ?? a5 40 00}  //weight: 8, accuracy: Low
        $x_1_3 = "ShutdownBlockReasonDestroy" ascii //weight: 1
        $x_1_4 = "FlushProcessWriteBuffers" ascii //weight: 1
        $x_3_5 = "PSXPSXPSXPSXPSXPSXfffff" ascii //weight: 3
        $x_3_6 = "WinSCard.dll" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_7_*) and 1 of ($x_3_*))) or
            ((1 of ($x_8_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_3_*))) or
            ((1 of ($x_8_*) and 1 of ($x_7_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_CI_2147731216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CI"
        threat_id = "2147731216"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PSXPSXPSXPSXPSXPSXfffff" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CI_2147731216_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CI"
        threat_id = "2147731216"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 53 46 48 45 44 47 48 20 34 35 38 39 00 23 00 24 00 5e 00 54 00 47 00 52 00 23 00 24 00 25}  //weight: 1, accuracy: High
        $x_1_2 = "35kC848Cc+5VuyOuPI7mLV.pdb" ascii //weight: 1
        $x_1_3 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 4c 00 54 00 46 00 49 00 4c 00 38 00 30 00 4e}  //weight: 1, accuracy: High
        $x_1_4 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 6e 00 65 00 63 00 6b 00 6f}  //weight: 1, accuracy: High
        $x_1_5 = "C-on!iG5EsHwQL.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Emotet_CI_2147731216_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CI"
        threat_id = "2147731216"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "3Vv@p=i8qg.ylQJxx!l.pdb" ascii //weight: 1
        $x_1_2 = "DemoShield Designer@A macro is currently being recorded" wide //weight: 1
        $x_1_3 = "The operation is cancelled" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CJ_2147731262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CJ"
        threat_id = "2147731262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PSXPSXPSXPSXPSXPSXfffff" ascii //weight: 1
        $x_1_2 = "WinSCard.dll" ascii //weight: 1
        $x_1_3 = "kbdth3 (3.13)" ascii //weight: 1
        $x_1_4 = "Stoh Levadihote (non-ShiftLock) Keyboa" wide //weight: 1
        $x_1_5 = "Thai Pattachote (non-ShiftLock) Keyboa" wide //weight: 1
        $x_1_6 = "Microsoft Video Studio Mono Builder DLL" wide //weight: 1
        $x_1_7 = "LEADTOOLS\\xae DLL for Win32" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Emotet_CK_2147731264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CK"
        threat_id = "2147731264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LQYutoXRJpQBI-zyVe.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CL_2147731268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CL"
        threat_id = "2147731268"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VLAH_2_acrjo.pdb" ascii //weight: 1
        $x_1_2 = "%4CqSjMpkI&" ascii //weight: 1
        $x_1_3 = "Key \"%s\" not found%goColMoving is not a supported option%Key may not contain equals sign (\"=\")" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CM_2147731273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CM"
        threat_id = "2147731273"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WGHWEh#gBWRG###@35TGWEg///GEW.pdb" ascii //weight: 1
        $x_1_2 = "QEhjejeher" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CN_2147731281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CN"
        threat_id = "2147731281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 57 52 4a 52 45 47 52 45 4a 45 47 23 ?? ?? ?? ?? ?? ?? ?? ?? (23|24|45|65|47|48|68|6a|6e|52|00) (23|24|45|65|47|48|68|6a|6e|52|00) 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 57 52 4a 52 45 47 52 45 4a 45 47 23 1d 00 00 ?? ?? ?? ?? ?? ?? ?? ?? (23|24|45|65|47|48|68|6a|6e|52|00) (23|24|45|65|47|48|68|6a|6e|52|00) 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_CQ_2147731296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CQ"
        threat_id = "2147731296"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ws7e7Y3=s5_nQx.pdb" ascii //weight: 1
        $x_1_2 = "slcoinst.dll" wide //weight: 1
        $x_1_3 = "Soft Modem" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CR_2147731309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CR"
        threat_id = "2147731309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hbthevby0Nmakes" ascii //weight: 1
        $x_1_2 = "O5BxjQHTTP143m" ascii //weight: 1
        $x_1_3 = {35 00 34 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 48 00 51 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 69 00 6e 00 74 00 65 00 72 00 72 00 75 00 70 00 74 00 28 00 75 00 73 00 65 00 72 00 00 00 39 00 42 00 74 00 68 00 65 00 45 00 61 00 73 00 74 00 65 00 72 00 31 00 62 00 67 00 39 00 28 00 6f 00 72 00 44 00 65 00 63 00 65 00 6d 00 62 00 65 00 72 00 00 00 63 00 68 00 65 00 62 00 75 00 74 00 37 00 37 00 37 00 37 00 46 00 6f 00 72 00 50 00 61 00 6e 00 64 00 69 00 74 00 4f 00 00 00 69 00 6e 00 6f 00 66 00 68 00 74 00 68 00 65 00 63 00}  //weight: 1, accuracy: High
        $x_1_4 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 4f 00 67 00 67 00 53 00 6f 00 75 00 6e 00 64 00 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CS_2147731319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CS"
        threat_id = "2147731319"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "28723_92346_2394_FFFA" ascii //weight: 1
        $x_1_2 = "ZombifyActCtx" ascii //weight: 1
        $x_1_3 = "lvd*0j?#Fg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CV_2147731325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CV"
        threat_id = "2147731325"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YActiveXanderGhGinstallationB" ascii //weight: 1
        $x_1_2 = "InternetiinstancebeenCC." ascii //weight: 1
        $x_1_3 = "Microsoft Corporatio" wide //weight: 1
        $x_1_4 = "DemoShield Designer@A macro is currently being recorded" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CU_2147731328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CU"
        threat_id = "2147731328"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "+p2zdX0SD1KML9=FCmr" ascii //weight: 2
        $x_2_2 = "LOIIccAQ.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CX_2147731329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CX"
        threat_id = "2147731329"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d c2 0c 00 89 35 ?? ?? 51 00 e8 ?? ?? ff ff 89 45 fc c3 5a 01 ca 89 15}  //weight: 1, accuracy: Low
        $x_1_2 = "##GWEHJETKETRREJREUER***" ascii //weight: 1
        $x_1_3 = "DemoShield Designer" wide //weight: 1
        $x_3_4 = "r4b5led=\"Trunurty.pdb" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_CY_2147731341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CY"
        threat_id = "2147731341"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {01 fe 8b 7c 24 28 81 cf 03 a0 7b 6e 8b 5c 24 30 89 9c 24 cc 00 00 00 89 bc 24 c8 00 00 00 89 74 24 78 35 72 4c fc 17 09 c8 89 44 24 20 75 02}  //weight: 2, accuracy: High
        $x_2_2 = "KncfQC.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DA_2147731372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DA"
        threat_id = "2147731372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "g6s9S.pdb" ascii //weight: 1
        $x_1_2 = "IgrSO5qEhHX.pdb" ascii //weight: 1
        $x_1_3 = "G.Yc.wcr.pdb" ascii //weight: 1
        $x_1_4 = "x86\\RunDll.pdb" ascii //weight: 1
        $x_2_5 = "PSXPSXPSXPSXPSXPSXU" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_RB_2147731391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RB"
        threat_id = "2147731391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NDdtN#joKc7.pdb" ascii //weight: 1
        $x_1_2 = "chebut7777ForPanditO" wide //weight: 1
        $x_1_3 = "9BtheEaster1bg9(orDecember" wide //weight: 1
        $x_1_4 = "Chrome  (notiwantuMthe" wide //weight: 1
        $x_1_5 = "Browser private 17fYuse66Dev" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RA_2147731401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RA"
        threat_id = "2147731401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#HEJeRTE$3#@.pdb" ascii //weight: 1
        $x_1_2 = "clientID111a4zzzzzzcoordinatedTheotherOplug-insY" wide //weight: 1
        $x_1_3 = "amanagementXworkarounds2alongnLq" wide //weight: 1
        $x_1_4 = "bonniecompetitorsfextensionseagle1as" wide //weight: 1
        $x_1_5 = "releaseinstancebenjaminRas49cupdates.92" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CZ_2147731417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CZ"
        threat_id = "2147731417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "eHWRHGBwrneERbREBNWR" wide //weight: 1
        $x_1_2 = "Adapted from PuTTY plink (http://www.chiark.greenend.org.uk/" wide //weight: 1
        $x_1_3 = "Microsoft C" wide //weight: 1
        $x_1_4 = "TortoisePlink.exe" wide //weight: 1
        $x_1_5 = "esvn.net" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CZ_2147731417_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CZ"
        threat_id = "2147731417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 00 68 00 72 00 6f 00 6d 00 65 00 33 00 37 00 61 00 46 00 69 00 72 00 65 00 66 00 6f 00 78 00 00 00 61 00 73 00 4f 00 6e 00 4d 00 66 00 6f 00 72 00 77 00 61 00 72 00 64}  //weight: 1, accuracy: High
        $x_1_2 = {54 45 53 54 41 50 50 2e 45 58 45 00 6b 00 73 00 39 00 34 00 33 00 6d 00 73 00 77 00 61 00 73 00 64 00 66 00 00 00 39 32 33 6a 73 64 39 73}  //weight: 1, accuracy: High
        $x_1_3 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 56 00 56 00 42 00 42 00 42 00 63 00 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DB_2147731463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DB"
        threat_id = "2147731463"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MIwmTQpFxHs.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CG_2147731635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CG"
        threat_id = "2147731635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bRWJerhWE#.pdb" ascii //weight: 1
        $x_1_2 = "QllZd.dll" wide //weight: 1
        $x_1_3 = "QllZad" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DC_2147731636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DC"
        threat_id = "2147731636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "9may12hfX" wide //weight: 1
        $x_1_2 = "pepperptofasterExtensionsdownL" wide //weight: 1
        $x_1_3 = "dOSnkofsavingdrewU" wide //weight: 1
        $x_1_4 = "andJ0potentiallythistoryinyclaimed" wide //weight: 1
        $x_4_5 = "Fg8/7|5P#Rld/2fCFP0Z9nt.pdb" ascii //weight: 4
        $x_4_6 = "Kcerqphlwbhq23v2RClk/=I9/Y.pdb" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_DE_2147731699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DE"
        threat_id = "2147731699"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0D0H0L0P0T0X0" ascii //weight: 1
        $x_1_2 = "@@#@GWRBWe@@" wide //weight: 1
        $x_1_3 = "UnrealizeObject.PDB" ascii //weight: 1
        $x_2_4 = "Again\\forestuse.pdb" ascii //weight: 2
        $x_2_5 = "Yr77|1uygw..pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_DE_2147731699_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DE"
        threat_id = "2147731699"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-Uwki9yC1Ax.pdb" ascii //weight: 1
        $x_1_2 = "37743_dvdadopw+.pdb" ascii //weight: 1
        $x_1_3 = "_EIzyRQm8sI.Ne98PRlGTuVnol.pdb" ascii //weight: 1
        $x_1_4 = "berJRWehwbenETMBwvev324Y123rFGBE.Pdb" ascii //weight: 1
        $x_1_5 = "BI2AH.pdb" ascii //weight: 1
        $x_1_6 = "BU424ADZ+e7SQGkPF0_estdunmkI.pdb" ascii //weight: 1
        $x_1_7 = "c:\\consonant\\Steel\\postTold.pdb" ascii //weight: 1
        $x_1_8 = "c:\\electric\\radio\\problem\\whosebut.pdb" ascii //weight: 1
        $x_1_9 = "c:\\Often\\Four\\direct\\Divisionten.pdb" ascii //weight: 1
        $x_1_10 = "c:\\Wife\\High\\once\\HelpBetween.pdb" ascii //weight: 1
        $x_1_11 = "cVlU.pdb" ascii //weight: 1
        $x_1_12 = "dsTVjo.pdb" ascii //weight: 1
        $x_1_13 = "ehrjrhw.pdb" ascii //weight: 1
        $x_1_14 = "EHW#@YUJE%JE24t43@3S@.pdb" ascii //weight: 1
        $x_1_15 = "EWH#@1wHJnERbRW.Pdb" ascii //weight: 1
        $x_1_16 = "EWJERj#@$Jtejwre.pdb" ascii //weight: 1
        $x_1_17 = "EWJtCompositionWinwreQQQQQQQQQQQQQQQQQQQQQQ####.pdb" ascii //weight: 1
        $x_1_18 = "heEHRjtrkjW#@jet.pdb" ascii //weight: 1
        $x_1_19 = "hWEHW#@HJERKJERJER^$.Pdb" ascii //weight: 1
        $x_1_20 = "hwrhWHnehWR#@hWGWE\\\\\\ewhRELBwe\\\\.PDB" ascii //weight: 1
        $x_1_21 = "ikGLuNZj=X7A.pdb" ascii //weight: 1
        $x_1_22 = "JrekJW!#YJetje.pdb" ascii //weight: 1
        $x_1_23 = "Ki#HJTEJW#@YU%#$He.pdb" ascii //weight: 1
        $x_1_24 = "mhXrJRmJ.pdb" ascii //weight: 1
        $x_1_25 = "NDdtN#joKc7.pdb" ascii //weight: 1
        $x_1_26 = "pjZ*6dBR.pdb" ascii //weight: 1
        $x_1_27 = "rDtkt.pdb" ascii //weight: 1
        $x_1_28 = "vwe123#.PDB" ascii //weight: 1
        $x_1_29 = "wehjWEJHwle#L;.pdb" ascii //weight: 1
        $x_1_30 = "WEhW3yhERTjQ)E(RH)(*WR(.pdb" ascii //weight: 1
        $x_1_31 = "wGetExtWEJHwDiBuildClassI;.pdb" ascii //weight: 1
        $x_1_32 = "WHEew.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DF_2147731737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DF"
        threat_id = "2147731737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XyIRBtdFlMsI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DH_2147731763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DH"
        threat_id = "2147731763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "erherj#@!gberh.pdb" ascii //weight: 1
        $x_1_2 = "zq7zwega_jf.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DH_2147731763_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DH"
        threat_id = "2147731763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "z1e.bmai298RsBS2" ascii //weight: 1
        $x_1_2 = "veCg2J3swA/fqjP" wide //weight: 1
        $x_1_3 = "*gQFw/Z>8Xy=C7J5BxK" wide //weight: 1
        $x_1_4 = "C@ID3SLNr8" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Emotet_DI_2147731769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DI"
        threat_id = "2147731769"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xo2*W6y@d/m<#" wide //weight: 1
        $x_1_2 = "GCWYq1g.pdb" ascii //weight: 1
        $x_1_3 = "= =$=(=,=0=4=8=<=@=D=H=L=P=T=X=\\=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DI_2147731769_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DI"
        threat_id = "2147731769"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bsexyTrackingjordan23" ascii //weight: 1
        $x_1_2 = "/dQWPICl_Hude1v.pdb" ascii //weight: 1
        $x_1_3 = "gpeam+F/fbX" wide //weight: 1
        $x_1_4 = "sZlaunchedfuckoffjzGMAwhich" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Emotet_DI_2147731769_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DI"
        threat_id = "2147731769"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2c1313tkxads" wide //weight: 1
        $x_1_2 = "wJREje@#$YJErhqEWRJaj34.pdb" ascii //weight: 1
        $x_1_3 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 41 00 68 00 65 00 61 00 64 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 20 00 41 00 47}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_SL_2147731778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SL"
        threat_id = "2147731778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Skava LostWhosight Stickslave" wide //weight: 1
        $x_1_2 = {63 3a 5c 53 65 6c 66 5c 50 69 74 63 68 5c 4c 61 75 67 68 5c 50 6f 73 73 69 62 6c 65 53 65 63 74 69 6f 6e 2e 70 64 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DG_2147731825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DG"
        threat_id = "2147731825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 18 8b 74 24 04 8a 1c 31 2a 1c 15 ?? ?? ?? ?? 8b 54 24 14 88 1c 32}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 7d bf 2a 3c 32 00 df 8b 55 c0 01 d1 8b 75 e4 88 3c 16 83 c2 33}  //weight: 1, accuracy: High
        $x_1_3 = {8a 24 0a 28 c4 01 ce 39 df 88 65 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DJ_2147731840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DJ"
        threat_id = "2147731840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "T9bXMqev=9-yUPJ_I22.pdb" ascii //weight: 1
        $x_1_2 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 6b 00 62 00 64 00 62 00 75 00 20 00 28 00 33 00 2e 00 31 00 33 00 29 00 00 00 6e 00 48 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DJ_2147731840_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DJ"
        threat_id = "2147731840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rtjheWRJKeyWY@#yhJtrjER.pdb" ascii //weight: 1
        $x_1_2 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 50 00 72 00 69 00 6e 00 74 00 49 00 73 00 6f 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 48 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DK_2147731845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DK"
        threat_id = "2147731845"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "O7hSBMeQeIfm.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DK_2147731845_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DK"
        threat_id = "2147731845"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {71 48 65 72 71 65 68 65 72 48 68 00 65 72 23 56 31 32 68 74 72 40 40 6a 47 65 00 72 6a 65 65 77 00 34 23 48 52 45 4e 45}  //weight: 1, accuracy: High
        $x_1_2 = {68 00 77 00 72 00 4a 00 57 00 52 00 4a 00 45 00 72 00 00 00 6a 00 45 00 57 00 21 00 32 00 33 00 32 00 74 00 79 00 68 00 00 00 57 00 52 00 4a 00 40 00 23 00 54 00 59 00 48 00 45 00 52 00 6a 00 21 00 40 00 23}  //weight: 1, accuracy: High
        $x_1_3 = "twerkrtr###.pdb" ascii //weight: 1
        $x_1_4 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 53 00 50 00 52 00 65 00 76 00 69 00 65 00 77 00 2e 00 65 00 78 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DL_2147731848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DL"
        threat_id = "2147731848"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TESTAPP.EXE" ascii //weight: 1
        $x_1_2 = "ererY#W$HerhweHer.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DM_2147731860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DM"
        threat_id = "2147731860"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "legendUsingapplesh" wide //weight: 1
        $x_1_2 = "error78throughout(similarlogs" wide //weight: 1
        $x_1_3 = "WyourscannedIDlTCoey" wide //weight: 1
        $x_1_4 = "Uthe42C666666attemptcanadar" wide //weight: 1
        $x_1_5 = "SiSBase.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DN_2147731861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DN"
        threat_id = "2147731861"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "avzIJrtu!O@" wide //weight: 1
        $x_1_2 = "e125345232" wide //weight: 1
        $x_1_3 = "America Online, Inc." wide //weight: 1
        $x_1_4 = "MISCUTIL" wide //weight: 1
        $x_1_5 = "w125345232t125345232w125345232" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RC_2147731871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RC"
        threat_id = "2147731871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = ":Lkj3v,2u3=534v345b2345.PDB" ascii //weight: 5
        $x_5_2 = "WtakY0VNfo.pdb" ascii //weight: 5
        $x_5_3 = "BoRrTUJmtVT.pdb" ascii //weight: 5
        $x_5_4 = "IKlllQWgbhejkWEJKHw7\\\\werrnJEKLJ32hjelkk.PDB" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DO_2147731872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DO"
        threat_id = "2147731872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GWEG##REh" ascii //weight: 1
        $x_1_2 = "HRWHwWEgwrgw.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DP_2147731895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DP"
        threat_id = "2147731895"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LKkasdflcawklbjlblknrwcltkxwbtclkwejbct0lwkbjgrxlwkmtrklwert.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DQ_2147731898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DQ"
        threat_id = "2147731898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Uq1e+>WJ&n=" wide //weight: 1
        $x_1_2 = "kZMbKw+o#7y" wide //weight: 1
        $x_1_3 = "gwergkjweoijg#@4hjnlwrkw.PDB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DR_2147731901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DR"
        threat_id = "2147731901"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mshortcuts(e.g.webotherfirstinstallationIUniversityby" wide //weight: 1
        $x_1_2 = "GME l PVff sw LQpy MwXVIo" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RD_2147731904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RD"
        threat_id = "2147731904"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "c:\\ground\\apple\\been\\flat\\Surprise\\market\\took\\slave\\oncetriangle.pdb" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DS_2147731921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DS"
        threat_id = "2147731921"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UqxIkBeNYhKR.pdb" ascii //weight: 1
        $x_1_2 = "2gerGW@4herhw*9283y4huWO.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DT_2147731928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DT"
        threat_id = "2147731928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lIFdrGkmBePss.pdb" ascii //weight: 1
        $x_1_2 = "/dQWPICl_Hude1v.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DT_2147731928_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DT"
        threat_id = "2147731928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Acid3DiZauto-updatingPwasa" ascii //weight: 1
        $x_1_2 = "MayjeAThetoyotaIof2008" ascii //weight: 1
        $x_1_3 = "sZlaunchedfuckoffjzGMAwhich" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DU_2147731929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DU"
        threat_id = "2147731929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {23 00 68 00 65 00 72 00 65 00 48 00 52 00 45 00 54 00 40 00 23 00 68 00 65 00 72 00 77 00 48 00 52 00 45 00 54 00 40 00 23 00 68 00 65 00 72 00 24 00 48 00 52 00 45 00 [0-832] 00}  //weight: 5, accuracy: Low
        $x_2_2 = "F1j5HfqhrQ3" wide //weight: 2
        $x_2_3 = "5sYEIdfkqgo" wide //weight: 2
        $x_2_4 = ".jnbcf" ascii //weight: 2
        $x_2_5 = "Canadian M" wide //weight: 2
        $x_1_6 = "Nero Burning ROM" wide //weight: 1
        $x_1_7 = "Microsoft Corp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_DX_2147731936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DX"
        threat_id = "2147731936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 2e 06 36 30 90 a0 79 a7 5e 2d 3c a6 1a 67 63 2a 17 58 ab 4b 69 3b 94 28 b4 3f 91 86 0f ac 89 71 67 1c c0 7d 91 8f 11 15 7a 97 09 bc 17 10 c7 77 b8 09 2e 06 36 30 90 a0 79 a7 5e 82 c5 8b 71 bd e6 16 27 e3 f0 5b f4 88 a0 b3 09 47 14 7e 0f 35 ce 65 f0 69 b0 06 e6 7b 85 38 ab 57 92 01 ff fb c7 02 fd f1 b9 53 26 ba a4 a1 04 1c 4a b5 50 ac 9d 27 64 b5 94 4c e4 43 f2 80 7c 9d 98 ca d6 72 92 70 99 cf c6 79 83 d2 1a 74 67 98 66 ab 94 01 27 9b 14 83 43 5e 36 89 2e 30 19 e5 71 30 ab 21 c5 fb 0a db 7e 15 39 e3 f0 37 f4 88 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DV_2147731950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DV"
        threat_id = "2147731950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hJrj32hW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DW_2147731951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DW"
        threat_id = "2147731951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "avzIJrtu!O@" wide //weight: 1
        $x_1_2 = "QX#iGCTiTmTZtM5DjE5u-WW8X" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DY_2147731952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DY"
        threat_id = "2147731952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GME l PVff sw LQpy MwXVIo" wide //weight: 1
        $x_1_2 = "zif-ather-default-Chrome-continuous-lyd" wide //weight: 1
        $x_1_3 = "features7446,John10-dayn dolphin stiggere" wide //weight: 1
        $x_1_4 = "badboy the a were test,fof" wide //weight: 1
        $x_1_5 = "Mshortcuts(e.g.webotherfirstinstallationIUniversityby" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DZ_2147731974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DZ"
        threat_id = "2147731974"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "afterinstancestableDropboxiEasteravailablevirtualfirst" ascii //weight: 1
        $x_1_2 = "hwithupdates.193GoogleDownloadedoneC0coordinatedpassage" ascii //weight: 1
        $x_1_3 = "developers,toNTheyS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_EB_2147731996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.EB"
        threat_id = "2147731996"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "47A/KQDS+" wide //weight: 1
        $x_1_2 = "Xge4y7B<093" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_EE_2147731997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.EE"
        threat_id = "2147731997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "webexclusionusedreflectsInternetallowsUpdateoffer" ascii //weight: 1
        $x_1_2 = "wDevhtransitions,6Sjail.82008,frequent" ascii //weight: 1
        $x_1_3 = "accordingAChromewSecurityYandpreviously8" ascii //weight: 1
        $x_1_4 = "userslyet.133DeveloperCanarytomcat" wide //weight: 1
        $x_1_5 = "nathanSnxlocalnocontrolcycles.security" wide //weight: 1
        $x_1_6 = "seofnumber3ChromeXversionL" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Emotet_EF_2147731998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.EF"
        threat_id = "2147731998"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "avzIJrtu!O@" wide //weight: 1
        $x_1_2 = "w125345232t125345232" wide //weight: 1
        $x_1_3 = "t125345232t125345232w125345232" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_ED_2147731999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.ED"
        threat_id = "2147731999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IKlllQWgbhejkWEJKHw7\\\\werrnJEKLJ32hjelkk.PDB" ascii //weight: 1
        $x_1_2 = "rej42y4her\\\\hjert\\\\wtjerhreh.pdb" ascii //weight: 1
        $x_1_3 = "4icemanJgused" ascii //weight: 1
        $x_1_4 = "xRlMpqLSaluM.pdb" ascii //weight: 1
        $x_1_5 = "5334g42g\\\\ehre\\\\eh#HENr.pdb" ascii //weight: 1
        $x_1_6 = "eaFB47#j1t3cpJIbMqD34.pdb" ascii //weight: 1
        $x_1_7 = "#ikx6u!O*KW+*Lv0qKf.pdb" ascii //weight: 1
        $x_1_8 = "YmAGxf1R..pdb" ascii //weight: 1
        $x_1_9 = "6zyA6@267=HPS.C|dMqd4-qaN|yjm.pdb" ascii //weight: 1
        $x_1_10 = "kNxEnEJ*X=b=8u3+o#6L9w9dg596.pdb" ascii //weight: 1
        $x_1_11 = "kJRGEW!#HWRw\\\\\\EWJRERWhlkwRj@#WKLHKE:L.pdb" ascii //weight: 1
        $x_1_12 = "3\\\\qwhW#jerjw\\erjw#HJERjwr\\\\.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_EC_2147732002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.EC"
        threat_id = "2147732002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\supply\\trouble\\Classwho.pdb" ascii //weight: 1
        $x_1_2 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 54 00 6f 00 6f 00 77 00 61 00 69 00 74 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_EI_2147732016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.EI"
        threat_id = "2147732016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BY_EMOTET.1" ascii //weight: 1
        $x_1_2 = "PY_EMOTET" ascii //weight: 1
        $x_1_3 = "##########(((()))))cOde-PASSWORD!!!.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_EI_2147732016_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.EI"
        threat_id = "2147732016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WHE@#hjerhEWH\\\\ehre\\\\eh#HENr.pdb" ascii //weight: 1
        $x_1_2 = "o563p45m6p35v84068345v638456v83045p6.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_EJ_2147733284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.EJ"
        threat_id = "2147733284"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "e9exposed24engine.135E2" wide //weight: 1
        $x_1_2 = "cumshotcparties4123456England.p" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_EK_2147733295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.EK"
        threat_id = "2147733295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 34 35 03 0e 6c 7c 8b 4c 24 10 8b 54 24 14 89 11 89 44 24 ?? eb 99 8b 44 24 ?? 8b 4c 24 ?? 89 c2 81 f2 e7 c1 4e 0c 89 54 24 ?? 89 4c 24 ?? 8b 54 24 ?? 8b 74 24 ?? 66 8b 7c 24 ?? 31 db 89 44 24 0c b8 e7 2d 62 a5 89 4c 24 ?? 8b 4c 24 0c 29 c8 8b 4c 24 ?? 19 cb 66 89 7c 24 ?? 31 f3 31 d0 09 d8 89 44 24 ?? 74 af e9 74 ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 c0 8b 4d c4 ba 41 43 96 5f be 71 43 96 5f 8b 7d ?? 8b 5d ?? 2b 75 ?? 89 45 ?? 89 c8 89 4d ?? 31 c9 89 55 ?? 89 ca f7 f6 8b 4d ?? 29 d9 81 c7 c4 bc 69 a0 8b 75 ?? 21 fe 8b 7d}  //weight: 1, accuracy: Low
        $x_1_3 = {39 cf 0f 47 f2 8b 0d ?? ?? ?? ?? 8b 55 b8 01 d7 8a 55 ?? 80 f2 76 2a 14 31 8b 4d ?? 8b 75 ?? 02 14 31 8b 5d ?? 81 c3 f4 bc 69 a0 8b 4d ?? 88 14 31 01 de 8b 5d e8 39 de 89 f9 89 75 ?? 89 4d ?? 89 7d ?? 0f 82 7a ff ff ff e9 00 ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_EG_2147733310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.EG"
        threat_id = "2147733310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hwithupdates.34 Google Downloade done C6 coordinated passage" ascii //weight: 1
        $x_1_2 = "after instance stable Dropbox Easter available virtual,first" ascii //weight: 1
        $x_1_3 = "developers,dtyh5345e4r" ascii //weight: 1
        $x_1_4 = "announcedwasT(basedSeelasttthumbnailsXP" ascii //weight: 1
        $x_1_5 = "OPartialrinstallationGrangersGoogleonrepresent" ascii //weight: 1
        $x_1_6 = "open.S9refersyvulnerabilities.messagezwalkerS" ascii //weight: 1
        $x_1_7 = "Betagpredictions111ataylorRZfirst" ascii //weight: 1
        $x_1_8 = "webexclusionusedreflectsInternetallowsUpdateoffer" ascii //weight: 1
        $x_1_9 = "newVhsynchronization0nthepreviously6the" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Emotet_EH_2147733311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.EH"
        threat_id = "2147733311"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jkler.pdb" ascii //weight: 1
        $x_1_2 = "rhklwejhkl#JKHLerkl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_EH_2147733311_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.EH"
        threat_id = "2147733311"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ewklhojwkl\\\\ehw\\\\werejWRK@jketjwrg.pdb" ascii //weight: 1
        $x_1_2 = "WEHKLJWKL#@.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_EM_2147733315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.EM"
        threat_id = "2147733315"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "architectureotheAnnouncement" ascii //weight: 1
        $x_1_2 = "mouse-clickingWusage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_EL_2147733316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.EL"
        threat_id = "2147733316"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "YumDWP.pdb" ascii //weight: 5
        $x_1_2 = "sC2wE@QeP%D" wide //weight: 1
        $x_5_3 = "tkWSu.pdb" ascii //weight: 5
        $x_1_4 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 42 00 69 00 74 00 73 00 50 00 65 00 72 00 66 00 2e 00 64 00 6c 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_EN_2147733318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.EN"
        threat_id = "2147733318"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lkwrljHKL23klhj;metk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_EO_2147733340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.EO"
        threat_id = "2147733340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {61 72 63 68 69 74 65 63 74 75 72 65 20 6f 66 20 74 68 65 20 41 6e 6e 6f 75 6e 63 65 6d 65 6e 74 00 6d 6f 75 73 65 2d 63 6c 69 63 6b 20 69 6e 20 67 34 20 75 73 61 67 65}  //weight: 2, accuracy: High
        $x_1_2 = "sm5inYdays.197extensions" ascii //weight: 1
        $x_1_3 = "of2dH(donkey)4553429If initial-for" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_DV_2147733420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DV!bit"
        threat_id = "2147733420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 30 8b 78 04 8b 58 08 8b 68 0c 8b 60 10 8b 40 14 ff e0}  //weight: 1, accuracy: High
        $x_1_2 = {15 18 00 00 00 31 ?? 8b ?? 30 8b ?? 0c}  //weight: 1, accuracy: Low
        $x_1_3 = {31 d2 f7 f1 8b 0d ?? ?? ?? ?? 8a 1c 11 8b 4d ?? 8b 55 ?? 8a 3c 11 28 df 88 3c 11 81 c2 ff 00 00 00 8b 75 ?? 39 f2 89 55 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_EQ_2147733606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.EQ"
        threat_id = "2147733606"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NChromeLxavierrprotocolGoogle9Kand" wide //weight: 1
        $x_1_2 = "yswitchUpdate6njJYpubliclyapproximately" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_A_2147733692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.A!MTB"
        threat_id = "2147733692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=4p88E58GC_VZZF-1t.pdb" ascii //weight: 1
        $x_1_2 = "previews41georgeKtc" wide //weight: 1
        $x_1_3 = "Ofcoursetheremaybesomedangers" wide //weight: 1
        $x_1_4 = "SincefLbeGoogletheappointment" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_A_2147733692_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.A!MTB"
        threat_id = "2147733692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dsystemsmmechanismiszGallery).162for" wide //weight: 1
        $x_1_2 = "BetaVrelease2010whenstartsapplications.157" wide //weight: 1
        $x_1_3 = "5LNsitesgomanagementass" wide //weight: 1
        $x_1_4 = "IuYgpdEtSkZR2+in#e%r" wide //weight: 1
        $x_1_5 = "andIrearranged,tracked.underT0P" ascii //weight: 1
        $x_1_6 = "Messenger172beshare.30internetensuresas" ascii //weight: 1
        $x_1_7 = "often.293accordinguser.69In2" ascii //weight: 1
        $x_1_8 = "1IuYgpdEtSkZR2+in#e%r" wide //weight: 1
        $x_1_9 = "form be 5654 performance 4563 the it and" ascii //weight: 1
        $x_1_10 = "4353 godzilla On AP" wide //weight: 1
        $x_1_11 = "wdNGXafwVBvGf ov VuROFCOEVpWiJa SymjQlTcUzg" wide //weight: 1
        $x_1_12 = "aJHkNWcfzQ-vsYnJX" ascii //weight: 1
        $x_1_13 = "jthatappUpdate,Qflusess" ascii //weight: 1
        $x_1_14 = "WgeminiL0s2010,about:labs,twotheu" ascii //weight: 1
        $x_1_15 = "owMancrashdevelopersPhilippN61" ascii //weight: 1
        $x_1_16 = "Fuinstallation.117bGoogletGfour-partZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Emotet_ER_2147733787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.ER"
        threat_id = "2147733787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rather8desireyuserfallbackChromiummenumemberOmnibox" ascii //weight: 1
        $x_1_2 = "Imte#%fU5az-hd>*/vGk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_KA_2147733912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.KA!bit"
        threat_id = "2147733912"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 01 8b ?? ?? ?? 88 14 06 8b ?? ?? ?? 81 cf ?? ?? ?? ?? 89 ?? ?? ?? 66 8b ?? ?? ?? 66 83 f3 ff 83 c0 01 66 89 ?? ?? ?? 8b ?? ?? ?? 39 f8 89 ?? ?? ?? 74 af}  //weight: 1, accuracy: Low
        $x_1_2 = {66 8b 14 41 66 89 d6 66 83 c6 bf 66 89 d7 66 83 c7 20 66 83 fe 1a 66 0f 42 d7 8b ?? ?? ?? 66 39 14 43 0f 94 c1 83 c0 01 8b ?? ?? ?? 39 f0 0f 92 c5 66 83 fa 00 0f 95 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_P_2147733945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.P!MTB"
        threat_id = "2147733945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 40 68 00 30 00 00 50 6a 00 55 ff d7}  //weight: 1, accuracy: High
        $x_1_2 = {8d 44 24 30 50 51 56 ff 54 24 38 83 c4 1c ff d6 5f 5e 5d 33 c0 5b 83 c4 38 c3}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 6a 00 56 6a 00 6a 01 55 57 ff 15 ?? ?? ?? ?? 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_4 = "SOFTWARE\\Bubble Breaker" wide //weight: 1
        $x_1_5 = "CryptStringToBinaryA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_ES_2147734102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.ES"
        threat_id = "2147734102"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Qmechanisms.108otherqwolf" wide //weight: 1
        $x_1_2 = "address.115is9Exploreralsowith3D" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_ET_2147734129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.ET"
        threat_id = "2147734129"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Qmechanisms.108otherqwolf" wide //weight: 1
        $x_1_2 = "address.115is9Exploreralsowith3D" wide //weight: 1
        $x_1_3 = "\\\\smb.microsoft.com\\share\\dev.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PA_2147734474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PA!MTB"
        threat_id = "2147734474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 57 eb 00 a1 ?? ?? ?? 00 a3 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 8b 11 89 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 2d ?? ?? ?? ?? a3 ?? ?? ?? 00 8b 15 ?? ?? ?? 00 81 c2 ?? ?? ?? ?? a1 ?? ?? ?? 00 8b ff 8b ca a3 ?? ?? ?? 00 [0-32] 31 ?? ?? ?? ?? 00 a1 ?? ?? ?? 00 8b ff c7 05 ?? ?? ?? 00 00 00 00 00 8b ff 01 05 ?? ?? ?? 00 8b ff 8b 0d ?? ?? ?? 00 8b 15 ?? ?? ?? 00 89 11 5f 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d f8 3b [0-5] 72 ?? eb ?? 8b 55 ?? 89 55 ?? c7 45 f0 ?? ?? ?? ?? 8b 45 ?? 03 45 ?? c6 00 00 c7 45 f0 00 00 00 00 [0-64] 88 [0-2] c7 45 f0 ?? ?? ?? ?? 8b ?? ?? 83 ?? ?? 89 ?? ?? (eb|e9)}  //weight: 1, accuracy: Low
        $x_1_3 = {55 8b ec 57 [0-2] a1 ?? ?? ?? 00 a3 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 8b 11 89 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 83 e8 ?? a3 ?? ?? ?? 00 [0-48] 8b 15 ?? ?? ?? 00 [0-96] 83 c2 ?? [0-2] a1 ?? ?? ?? 00 [0-2] 8b ca [0-2] a3 ?? ?? ?? 00 [0-48] (31 0d ?? ?? ?? 00 a1 ?? ?? ??|33 c1) [0-2] c7 05 ?? ?? ?? 00 00 00 00 00 [0-2] 01 05 ?? ?? ?? 00 [0-2] 8b 0d ?? ?? ?? 00 8b 15 ?? ?? ?? 00 89 11 [0-1] 5d c3}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 4d f8 3b 4d 08 72 ?? e9 ?? ?? ?? ?? 8b 55 ?? 89 55 ?? c7 45 f0 ?? ?? ?? ?? 8b 45 ?? 03 45 ?? c6 00 00 c7 45 f0 00 00 00 00 8b 4d ?? ?? 4d ?? ?? 4d ?? ?? 0d ?? ?? ?? 00 ?? 0d ?? ?? ?? 00 ?? 0d ?? ?? ?? 00 ?? 0d ?? ?? ?? 00 [0-24] 8b 55 ?? ?? 55 ?? ?? 55 ?? ?? 15 ?? ?? ?? 00 ?? 15 ?? ?? ?? 00 ?? 15 ?? ?? ?? 00 ?? 15 ?? ?? ?? 00 [0-24] 8b 45 ?? 8b 75 ?? 8a 0c 0e 88 0c 10 c7 45 f0 ?? ?? ?? ?? 8b 55 ?? 83 c2 01 89 55 ?? e9}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 4d f8 3b 4d 08 72 ?? e9 ?? ?? ?? ?? 8b 55 ?? 89 55 ?? c7 45 f0 ?? ?? ?? ?? 8b 45 ?? 03 45 ?? c6 00 00 c7 45 f0 00 00 00 00 [0-240] 88 ?? ?? c7 45 f0 ?? ?? ?? ?? 8b ?? f8 83 ?? 01 89 ?? f8 e9}  //weight: 1, accuracy: Low
        $x_1_6 = {55 8b ec 51 8b 45 0c 89 45 fc 8b 0d ?? ?? ?? 00 89 4d 08 8b 55 08 8b 02 8b 4d fc 8d [0-6] 8b 45 08 89 10 8b 4d 08 8b 11 (81|83) [0-5] 8b 45 08 89 10 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 4d f8 3b [0-5] 72 ?? eb ?? 8b 55 ?? 89 55 [0-96] 8b 4d ?? 8b 55 ?? 8a 04 ?? 88 ?? ?? 8b ?? ?? 83 ?? ?? 89 ?? ?? (eb|e9)}  //weight: 1, accuracy: Low
        $x_1_8 = {8b 4d f8 3b 0d ?? ?? ?? 00 72 ?? eb ?? 8b 55 ?? 03 55 ?? 8b 45 ?? 03 45 ?? 8a 08 88 0a 8b 55 ?? 83 c2 01 89 55 ?? eb}  //weight: 1, accuracy: Low
        $x_1_9 = {55 8b ec a1 ?? ?? ?? 00 a3 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 8b 11 89 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 83 e8 ?? a3 ?? ?? ?? 00 [0-192] 8b 15 ?? ?? ?? 00 [0-160] 83 c2 ?? [0-48] a1 ?? ?? ?? 00 [0-5] 8b ca [0-2] a3 ?? ?? ?? 00 [0-176] (31 0d ?? ?? ?? 00 a1 ?? ?? ??|33 c1) [0-2] c7 05 ?? ?? ?? 00 00 00 00 00 [0-2] 01 05 ?? ?? ?? 00 [0-2] 8b 0d ?? ?? ?? 00 8b 15 ?? ?? ?? 00 89 11 [0-1] 5d c3}  //weight: 1, accuracy: Low
        $x_1_10 = {55 8b ec 56 [0-3] a1 ?? ?? ?? 00 a3 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 8b 11 89 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 83 e8 ?? a3 ?? ?? ?? 00 [0-48] 8b 15 ?? ?? ?? 00 83 c2 ?? a1 ?? ?? ?? 00 [0-2] 8b ca a3 ?? ?? ?? 00 [0-48] (31 0d ?? ?? ?? 00 a1 ?? ?? ??|33 c1) [0-2] c7 05 ?? ?? ?? 00 00 00 00 00 [0-2] 01 05 ?? ?? ?? 00 [0-2] 8b 0d ?? ?? ?? 00 8b 15 ?? ?? ?? 00 89 11 [0-2] 5d c3}  //weight: 1, accuracy: Low
        $x_1_11 = {55 8b ec a1 ?? ?? ?? 00 a3 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 8b 11 89 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 83 e8 ?? a3 ?? ?? ?? 00 [0-192] 8b 15 ?? ?? ?? 00 83 c2 ?? a1 ?? ?? ?? 00 [0-2] 8b ca [0-2] a3 ?? ?? ?? 00 (31 0d ?? ?? ?? 00 a1 ?? ?? ??|90 02) b0 33 c1 [0-2] a3 ?? ?? ?? 00 [0-2] 8b 0d ?? ?? ?? 00 8b 15 ?? ?? ?? 00 89 11 [0-1] 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Emotet_KB_2147734510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.KB!bit"
        threat_id = "2147734510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 0e 8d 52 08 33 4d f4 8d 76 04 0f b6 c1 43 66 89 42 f8 8b c1 c1 e8 08 0f b6 c0 66 89 42 fa c1 e9 10 0f b6 c1 66 89 42 fc c1 e9 08 0f b6 c1 66 89 42 fe 3b df 72 c9}  //weight: 2, accuracy: High
        $x_2_2 = {8b 16 8d 49 04 33 55 0c 8d 76 04 88 51 fc 8b c2 c1 e8 08 47 c1 ea 10 88 41 fd 88 51 fe c1 ea 08 88 51 ff 3b fb 72 d9}  //weight: 2, accuracy: High
        $x_1_3 = {ba 87 82 43 54 b9 ?? ?? ?? 00 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_4 = {ba 66 5c 89 60 b9 ?? ?? ?? 00 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_GP_2147734550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GP"
        threat_id = "2147734550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "previews41georgeKtc" wide //weight: 1
        $x_1_2 = "\\SOFTWARE\\DEVEL\\DEBUG.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BI_2147734603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BI!MTB"
        threat_id = "2147734603"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 14 c6 44 24 ?? ?? 8b 4c 24 ?? 8b 54 24 ?? f7 d1 f7 d2 8b 34 85 ?? ?? ?? ?? 89 54 24 ?? 89 4c 24 ?? 8b 4c 24 ?? 39 ce 89 44 24 ?? 89 74 24}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 08 b9 ?? ?? ?? ?? 66 8b 54 24 ?? 66 83 f2 ?? 66 89 54 24 ?? 8b 74 24 ?? 81 f6 ?? ?? ?? ?? c6 44 24 ?? ?? 8a 5c 24 ?? 2a 5c 24 ?? 89 44 24 ?? 31 d2 f7 f1 8a 3c 15}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4c 24 20 8b 54 24 04 8a 0c 11 88 5c 24 ?? 28 f9 8b 7c 24 ?? 88 0c 17 c7 44 24 2c ?? ?? ?? ?? 01 f2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GR_2147734862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GR"
        threat_id = "2147734862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "eTiq_WaEN__y9F89zLukjmM.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PF_2147735019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PF!bit"
        threat_id = "2147735019"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 18 8d b4 bd fc fb ff ff 88 5d ff 8b 1e 89 18 0f b6 5d ff 89 1e 8b 00 03 c3 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 8a 84 85 fc fb ff ff 30 82 ?? ?? ?? ?? 42 81 fa 4e 0e 00 00 72}  //weight: 1, accuracy: Low
        $x_1_2 = "sc delete WinDefend" ascii //weight: 1
        $x_1_3 = "powershell Set-MpPreference -DisableRealtimeMonitoring $true" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_YA_2147735050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.YA!MTB"
        threat_id = "2147735050"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 57 eb 00 a1 ?? ?? ?? 00 a3 ?? ?? ?? 00 8b ?? ?? ?? ?? 00 8b 11 89 ?? ?? ?? ?? 00 a1 ?? ?? ?? 00 83 ?? ?? a3 ?? ?? ?? 00 8b ?? ?? ?? ?? 00 83 ?? ?? a1 ?? ?? ?? 00 8b ff 8b ca a3 ?? ?? ?? 00 eb 01 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_EX_2147735093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.EX"
        threat_id = "2147735093"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {85 ff 74 22 29 c9 49 23 0a 83 c2 04 83 c1 ee 31 d9 8d 49 ff 89 cb 89 4e 00 83 ef 04 83 ee fc b9 ?? ?? ?? ?? ff e1}  //weight: 2, accuracy: Low
        $x_2_2 = {09 c6 56 81 f9 ?? ?? 00 00 74 1d 8b 03 8d 5b 04 83 e8 ?? 31 f8 48 89 c7 89 46 00 83 e9 fc 83 c6 04 b8 ?? ?? ?? ?? ff e0}  //weight: 2, accuracy: Low
        $x_1_3 = "ixxx_ro_e__Memory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_EX_2147735093_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.EX"
        threat_id = "2147735093"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 01 e8 08 04 00 00 83 c4 04 8b 0d 00 b2 41 00 89 0d ac b1 41 00 8b 15 0c b0 41 00 a1 c4 b1 41 00 8d 8c 10 68 2b 00 00 2b 4d f4 03 0d cc b1 41 00 89 0d cc b1 41 00 8b 15 cc b1 41 00 81 ea 68 2b 00 00 89 15 cc b1 41 00 a1 0c b0 41 00 03 45 f4 03 05 c8 b1 41 00 a3 c8 b1 41 00 8b 0d a8 b1 41 00 2b 0d ac b1 41 00 89 0d a8 b1 41 00 83 3d e8 b1 41 00 00 0f 85 54 ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 83 ec 08 8b 45 0c 89 45 fc c7 45 f8 01 00 00 00 8b 0d 38 b2 41 00 89 4d 08 8b 55 fc 83 c2 01 2b 55 f8 8b 45 08 03 10 8b 4d 08 89 11 8b e5 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PB_2147735130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PB!MTB"
        threat_id = "2147735130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 45 f8 8b 88 c1 e0 ff ff 89 0d ?? ?? ?? 00 [0-80] 8b 15 ?? ?? ?? 00 81 c2 c4 8e 60 01 89 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 03 45 f8 8b 0d ?? ?? ?? 00 89 88 c1 e0 ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PG_2147735183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PG!bit"
        threat_id = "2147735183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5b 53 83 c3 3c ff 33 5b f7 db 29 1c 24 5b 8d 9b b4 00 00 00 83 eb 10}  //weight: 1, accuracy: High
        $x_1_2 = {41 c7 41 01 6a 68 72 6b 51 8d 05 ?? ?? ?? ?? ff 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PC_2147735254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PC"
        threat_id = "2147735254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=du97Ha36leTRWr" ascii //weight: 1
        $x_1_2 = "x9njm&34a4seG6gfBc11" ascii //weight: 1
        $x_1_3 = "RCrp1te[9leTR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GS_2147735630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GS"
        threat_id = "2147735630"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jjrkioplakdertybfgtrtyuioplmkas" ascii //weight: 1
        $x_1_2 = "inaaaro_ess__mory" ascii //weight: 1
        $x_1_3 = "hirtuulAlloc" ascii //weight: 1
        $x_1_4 = "hhhnel32.dll" ascii //weight: 1
        $x_1_5 = "hxaqftme" ascii //weight: 1
        $x_1_6 = "uvphmmdshyv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GT_2147735646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GT"
        threat_id = "2147735646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XgnjMx34Ajse'hgf\"=11d=2c" ascii //weight: 1
        $x_1_2 = "KojkM1XuHyY+Hy9+?|NtE1OxBuA+>" ascii //weight: 1
        $x_1_3 = "?jNrSo}J$mErBn}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PD_2147739715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PD!MTB"
        threat_id = "2147739715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 16 8d 49 04 81 f2 ?? ?? ?? ?? 8d 76 04 88 51 fc 8b c2 c1 e8 08 47 c1 ea 10 88 41 fd 88 51 fe c1 ea 08 88 51 ff 3b fb 72}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 0e 8d 52 08 33 4d ?? 8d 76 04 0f b6 c1 43 66 89 42 f8 8b c1 c1 e8 08 0f b6 c0 66 89 42 fa c1 e9 10 0f b6 c1 66 89 42 fc c1 e9 08 0f b6 c1 66 89 42 fe 3b df 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DA_2147740086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DA!MTB"
        threat_id = "2147740086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 44 24 20 b8 02 00 00 00 2b c6 89 6c 24 14 2b c1 8d 6a fd 0f af c6 0f af ef 0f af d9 03 c5 8b 6c 24 34 83 c4 04 8d 04 40 2b c3 2b c2}  //weight: 10, accuracy: High
        $x_3_2 = "zdq11(ztgYEz_BNxWx<hWOrNAB4V4csuPHBg3vy" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DA_2147740086_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DA!MTB"
        threat_id = "2147740086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 56 50 8a 45 14 8b 4d 10 8b 55 0c 8b 75 08 b4 ?? c6 45 fb ?? 2a 65 fb 30 e0 02 04 0a 88 04 0e 83 c4 04 5e 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 1c 11 0f b6 fb 8b 4d d0 01 f9 89 c8 89 55 c8 99 f7 fe 8b 4d e0 8a 3c 11 8b 75 f0 81 f6 ?? ?? ?? ?? 89 55 c4 8b 55 c8 88 3c 11 8b 55 c4 88 1c 11 8b 4d f0 8b 55 e0 8b 5d c8 0f b6 14 1a 01 fa 81 c1 ?? ?? ?? ?? 21 ca 8b 4d e0 8a 0c 11 8b 55 e8 8b 7d cc 32 0c 3a 8b 55 e4 88 0c 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GW_2147741054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GW"
        threat_id = "2147741054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 5d f0 81 6d f0 ?? ?? ?? ?? 35 ?? ?? ?? ?? 81 6d f0 ?? ?? ?? ?? 81 45 f0 ?? ?? ?? ?? c1 e8 02 81 6d f0 ?? ?? ?? ?? c1 eb 17 81 45 f0 ?? ?? ?? ?? 35 ?? ?? ?? ?? 81 45 f0 ?? ?? ?? ?? 81 6d f0 ?? ?? ?? ?? c1 e0 1a 81 6d f0 ?? ?? ?? ?? 81 45 f0 ?? ?? ?? ?? 8b 45 f0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AD_2147741255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AD!ibt"
        threat_id = "2147741255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 01 33 d2 66 85 c0 74 30 8d 9b 00 00 00 00 66 83 f8 41 72 0e 66 83 f8 5a 77 08 0f b7 c0 83 c0 20 eb 03 0f b7 c0 69 d2 3f 00 01 00 83 c1 02 03 d0 0f b7 01 66 85 c0 75 d6 8b c2}  //weight: 1, accuracy: High
        $x_1_2 = {33 c0 59 c3 e8 43 c8 ff ff e8 ce c9 ff ff e8 e9 d8 ff ff e8 b4 e6 ff ff e8 df ea ff ff 83 ec 08 e8 c7 b6 ff ff 83 c4 08 85 c0 74 ca c7 05 ?? ?? ?? ?? b8 26 41 00 c7 05 ?? ?? ?? ?? f0 fb 40 00 c7 05 ?? ?? ?? ?? 6a 00 00 00 c7 05 ?? ?? ?? ?? 02 00 00 00 eb 89 c7 05 ?? ?? ?? ?? 02 00 00 00 e8 97 fd ff ff 59 c3 ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 33 c0 59}  //weight: 1, accuracy: Low
        $x_1_3 = {83 f8 03 0f 87 b8 00 00 00 ff 24 85 ?? ?? ?? ?? e8 f5 b9 ff ff e8 f0 bf ff ff e8 8b 22 00 00 85 c0 75 21 c7 05 ?? ?? ?? ?? 01 00 00 00 ff 15 ?? ?? ?? ?? 33 d2 b9 a0 0f 00 00 f7 f1 8d 82 a0 0f 00 00 59 c3}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 85 a0 fd ff ff 7e 6d 6f 77 c7 85 a4 fd ff ff de 73 3b 6e c7 85 a8 fd ff ff 1e 89 ec 57 c7 85 ac fd ff ff 37 b3 24 89 c7 85 b0 fd ff ff af 06 7d 16 c7 85 b4 fd ff ff e9 5d ac f9 c7 85 b8 fd ff ff d6 59 e6 e1 c7 85 bc fd ff ff 9f 03 69 fc c7 85 c0 fd ff ff d7 53 e0 58 c7 85 c4 fd ff ff 77 1b a1 28 c7 85 c8 fd ff ff 17 b5 d7 a6 c7 85 cc fd ff ff 33 d7 41 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_HA_2147741589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.HA"
        threat_id = "2147741589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SMALpOVI6Iui.pdb" ascii //weight: 1
        $x_1_2 = "DmMgMfxvsr.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DSK_2147742753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DSK!MTB"
        threat_id = "2147742753"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a bc 04 60 01 00 00 88 bc 0c 60 01 00 00 88 9c 04 60 01 00 00 42 89 8c 24 98 02 00 00 8b 8c 24 cc 00 00 00 81 c1 f5 10 ac b9 8b b4 24 c8 00 00 00 83 d6 ff 89 8c 24 b0 02 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_SB_2147742769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SB"
        threat_id = "2147742769"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "hncobjapi.dll" wide //weight: 5
        $x_5_2 = "hwsjkislopkjunhytgh" ascii //weight: 5
        $x_1_3 = "PhoneBookEnumNumbers" ascii //weight: 1
        $x_1_4 = "PhoneBookLoad" ascii //weight: 1
        $x_1_5 = "PhoneBookEnumCountries" ascii //weight: 1
        $x_1_6 = "PhoneBookFreeFilter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_BS_2147742862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BS!MTB"
        threat_id = "2147742862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 99 f7 fb 89 55 ?? 03 d7 52 51 e8 ?? ?? ?? ?? 8b 45 ?? 40 3b c6 59 59 89 45 ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BS_2147742862_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BS!MTB"
        threat_id = "2147742862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 fb 8b 45 ?? 0f b6 14 10 8b 45 ?? 0f be 1c 08 89 d8 21 d0 09 da 8b 5d ?? f7 d0 21 d0 88 04 0b 41 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BS_2147742862_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BS!MTB"
        threat_id = "2147742862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e1 ff 00 00 00 03 c1 b9 75 26 00 00 99 f7 f9 8b 45 ?? 8a 08 8a 94 15 ?? ?? ?? ?? 32 ca 88 08 40 89 45 ?? 8b 45 ?? 48 89 45 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BS_2147742862_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BS!MTB"
        threat_id = "2147742862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c3 99 f7 f9 0f b6 04 37 8b da 8a 14 33 88 14 37 88 04 33 0f b6 0c 33 0f b6 04 37 03 c1}  //weight: 1, accuracy: High
        $x_1_2 = {02 d2 8a cc c0 e9 04 02 d2 0a ca 88 0e 8a 4c 24 ?? 8a d1 8a c4 c0 e0 04 83 c6 01 c0 ea 02 0a d0 c0 e1 06 0a 4c 24 ?? 88 16 83 c6 01 88 0e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BS_2147742862_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BS!MTB"
        threat_id = "2147742862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b f0 89 44 24 ?? 89 74 24 ?? 89 4c 24 ?? b3 06 eb 08 8b 54 24 ?? 8b 7c 24 ?? 8d 42 01 b9 ?? ?? ?? ?? 99 f7 f9 33 c0 8a 04 2a 03 c7 89 54 24 ?? 8d 34 2a 99 f7 f9}  //weight: 1, accuracy: Low
        $x_1_2 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 0f b6 04 32 8b 54 24 10 0f be 3c 17 e8 ?? ?? ?? ?? 8b 4c 24 10 88 01 41 83 6c 24 14 01 89 4c 24 10 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_BS_2147742862_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BS!MTB"
        threat_id = "2147742862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "FDSADFXssdsdfggGSDZCSDewd" wide //weight: 1
        $x_1_2 = "uytyDDzxsdEQdssgGGSDSds" wide //weight: 1
        $x_1_3 = {6a 00 6a 00 6a 00 6a 00 68 ac 04 01 00 68 a7 ad 00 00 68 77 03 00 00 68 6b 03 00 00 68 00 00 80 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BS_2147742862_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BS!MTB"
        threat_id = "2147742862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 4c 24 1c 8b 84 24 ?? ?? ?? ?? 8a 54 14 20 30 14 01 41 89 4c 24 1c 8b 8c 24 ?? ?? ?? ?? 85 c9 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {03 c1 8b ce 99 f7 f9 8b 45 ?? 8a 8c 15 ?? ?? ?? ?? 30 08 40 ff 4d ?? 89 45 ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 4c 24 1c 8b 44 24 20 83 c1 01 89 4c 24 1c 8a 54 14 24 30 54 08 ff 83 bc 24 ?? ?? ?? ?? 00 0f 85}  //weight: 1, accuracy: Low
        $x_1_4 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 24 8a 4c 14 28 30 08 ff 44 24 1c 39 b4 24 ?? ?? ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_BS_2147742862_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BS!MTB"
        threat_id = "2147742862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {b8 5f 33 00 00 85 c0 74 ?? 8b 4d ?? 3b 0d ?? ?? ?? ?? 72 ?? eb ?? 8b 55 ?? 03 55 ?? 8b 45 ?? 03 45 ?? 8b 4d ?? 8b 75 ?? 8a 14 16 88 14 01 8b 45 ?? 83 c0 01 89 45 ?? eb}  //weight: 3, accuracy: Low
        $x_2_2 = {83 e9 01 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? b9 01 00 00 00 85 c9 0f}  //weight: 2, accuracy: Low
        $x_1_3 = {55 8b ec 51 a1 ?? ?? ?? ?? 89 45 fc eb 00 8b 65 fc 58 8b e8 a1 ?? ?? ?? ?? 50 a1 ?? ?? ?? ?? 50 ff 25 ?? ?? ?? ?? 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_6_4 = {81 ff d0 08 00 00 74 23 29 c0 48 23 02 83 ea fc 83 c0 dd 01 d8 83 c0 ff 89 c3 c7 01 00 00 00 00 09 01 83 c1 04 83 c7 04 2e}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_PE_2147742876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PE!MTB"
        threat_id = "2147742876"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b 11 f7 da 83 c1 04 83 ea 23 01 f2 83 ea 01 31 f6 29 d6 f7 de c6 07 00 01 17 8d 7f 04 8d 5b 04 2e eb}  //weight: 5, accuracy: High
        $x_1_2 = {11 23 67 45 [0-16] 11 23 67 45 [0-16] 11 23 67 45 [0-16] 00 00 00 00 [0-16] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BA_2147742937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BA!MTB"
        threat_id = "2147742937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 25 ff 00 00 80 79 ?? 48 0d 00 ff ff ff 40 89 45 ?? 8b 45 ?? 0f b6 88 ?? ?? ?? ?? 8b 55 ?? 0f b6 84 15 ?? ?? ?? ?? 33 c8 8b 55 ?? 88 8a ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BA_2147742937_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BA!MTB"
        threat_id = "2147742937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b c7 33 f6 89 74 24 14 8d 2c 08 8b 0d ?? ?? ?? ?? 8b f9 8b dd 0f af f9 0f af da 0f af fa}  //weight: 10, accuracy: Low
        $x_3_2 = "ErJIZwQ%B4X_#*TUuU32vx(c9_@8*C!Bi7dX7o" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BA_2147742937_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BA!MTB"
        threat_id = "2147742937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c6 99 be ?? ?? ?? ?? f7 fe 8a 44 8c 04 0f b6 c0 8b f2 8b 54 b4 10 89 54 8c 04 89 44 b4 10 33 d2 8d 47 ff f7 f3 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 44 8c 10 8b f2 8b 54 b4 10 89 54 8c 10 0f b6 d0 89 54 b4 10 8b 44 8c 10 03 c2 99 f7}  //weight: 1, accuracy: High
        $x_1_3 = {f7 fe 8a 44 8c 08 0f b6 c0 8b f2 8b 54 b4 10 89 54 8c 08 89 44 b4 10 33 d2 8b c7 f7 f3 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BA_2147742937_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BA!MTB"
        threat_id = "2147742937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "2ZTYXG7K5#RY+(uRRaE&LXIvF!+@>m779sEjBU)d(Mb3_!Z" ascii //weight: 3
        $x_3_2 = "DllRegisterServer" ascii //weight: 3
        $x_3_3 = "PathFindExtensionW" ascii //weight: 3
        $x_3_4 = "PathFindFileNameW" ascii //weight: 3
        $x_3_5 = "PathStripToRootW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BB_2147742938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BB!MTB"
        threat_id = "2147742938"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 8b 84 85 f0 f9 ff ff 8b 8d ec f9 ff ff 03 84 8d f0 f9 ff ff 99 b9 81 01 00 00 f7 f9 8b 45 08 03 45 f8 0f b6 08 33 8c 95 f0 f9 ff ff 8b 55 08 03 55 f8 88 0a e9}  //weight: 1, accuracy: High
        $x_1_2 = {8a 44 8c 10 8b da 8b 54 9c 10 89 54 8c 10 0f b6 d0 89 54 9c 10 8b 44 8c 10 03 c2 99 f7 ff 0f b6 44 94 10 30 44 2e ff 3b b4 24 9c 08 00 00 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_BB_2147742938_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BB!MTB"
        threat_id = "2147742938"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 d1 8b 4c 24 ?? 03 d0 8d 04 09 2b d0 8b 44 24 ?? 03 d5 8a 18 8a 0c 3a 32 d9 8b 4c 24 ?? 88 18 8b 44 24 ?? 40 3b c1 89 44 24 ?? 0f 82}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BB_2147742938_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BB!MTB"
        threat_id = "2147742938"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 6c 24 1c 8b 5c 24 20 03 c6 57 8b 7c 24 28 8d 04 40 c7 44 24 14 00 00 00 00 2b c7 03 c5 8d 5c 18 05 8d 41 01}  //weight: 10, accuracy: High
        $x_3_2 = "l##B+k&rB$cb^AHa54%*oDqeEuskFn8Vh@V4l" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PF_2147743037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PF!MTB"
        threat_id = "2147743037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 81 ec ?? ?? ?? ?? 8b 45 ?? 89 45 ?? 8b 0d ?? ?? ?? ?? 89 4d ?? [0-32] 8b 55 ?? 8b 02 8b 4d ?? 8d 94 01 ?? ?? ?? ?? 8b 45 ?? 89 10 8b 4d ?? 8b 11 81 ea ?? ?? ?? ?? 8b 45 ?? 89 10 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 57 [0-16] 8b 0d ?? ?? ?? ?? 8b 11 89 15 ?? ?? ?? ?? [0-128] a1 ?? ?? ?? ?? 8b ca a3 ?? ?? ?? ?? [0-192] 31 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b ff 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11 5f 5d c3}  //weight: 1, accuracy: Low
        $x_1_3 = {55 8b ec 57 [0-16] 8b 0d ?? ?? ?? ?? 8b 11 89 15 ?? ?? ?? ?? [0-64] a1 ?? ?? ?? ?? [0-48] a3 ?? ?? ?? ?? [0-240] a1 ?? ?? ?? ?? 33 c1 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b ff 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11 5f 5d c3}  //weight: 1, accuracy: Low
        $x_1_4 = {55 8b ec 57 [0-16] 8b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? [0-64] a1 ?? ?? ?? ?? [0-48] a3 ?? ?? ?? ?? [0-240] a1 ?? ?? ?? ?? 33 c1 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02 5f 5d c3}  //weight: 1, accuracy: Low
        $x_1_5 = {55 8b ec 51 57 [0-32] 8b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 [0-64] a1 [0-48] a3 00 02 a1 ?? ?? ?? ?? 33 c1 00 02 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b ff 00 02 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02 5f 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_6 = {55 8b ec 81 ec ?? ?? ?? ?? 8b 45 ?? 89 45 ?? 8b 0d ?? ?? ?? ?? 89 4d ?? [0-64] 8b 4d ?? 8d 94 01 8a 10 00 00 8b 45 08 03 10 8b 4d 08 89 11 8b 55 08 8b 02 2d 8a 10 00 00 8b 4d 08 89 01 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_7 = {55 8b ec 51 57 [0-32] 8b 0d ?? ?? ?? ?? 8b 11 89 15 [0-64] a1 [0-48] a3 00 02 a1 ?? ?? ?? ?? 33 c1 00 02 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b ff 00 02 8b 15 ?? ?? ?? ?? 89 11 5f 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_8 = {55 8b ec 51 8b 45 0c 89 45 fc 8b 0d ?? ?? ?? ?? 89 4d 08 8b 55 08 8b 02 8b 4d fc 8d 94 01 8a 10 00 00 8b 45 08 89 10 8b 4d 08 8b 11 81 ea 8a 10 00 00 8b 45 08 89 10 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Emotet_GG_2147743292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GG!MTB"
        threat_id = "2147743292"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 99 f7 ?? 0f ?? ?? ?? ?? 30 ?? ?? ?? 3b ?? ?? ?? ?? ?? ?? 72 71 00 8d [0-2] 99 b9 ?? ?? ?? ?? f7 ?? bf ?? ?? ?? ?? ?? 8b ?? 8b ?? ?? ?? 03 ?? 99 f7 ?? 8a ?? ?? ?? 8b da 8b 54 ?? ?? 89 ?? ?? ?? 0f b6 d0 89 54 ?? ?? 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GG_2147743292_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GG!MTB"
        threat_id = "2147743292"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 06 8b 4d [0-2] 5f 5e 64 [0-2] 00 00 00 00 5b c9 c2}  //weight: 1, accuracy: Low
        $x_1_2 = {6a ff 50 64 [0-2] 00 00 00 00 50 8b 44 [0-2] 64 [0-2] 00 00 00 00 89 6c [0-2] 8d 6c [0-2] 50 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 4c 24 10 e8 [0-30] ff 00 00 00 03 c1 b9 [0-4] 99 f7 f9 8d 4c [0-4] 32 9c 14}  //weight: 1, accuracy: Low
        $x_1_4 = "UnhookWindowsHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GG_2147743292_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GG!MTB"
        threat_id = "2147743292"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 00 00 00 00 50 83 ec [0-2] a1 [0-4] 33 c4 89 44 [0-2] 53 55 56 57 a1 [0-4] 33 c4 50 8d 44 [0-2] 64 [0-1] 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 04 0d 00 10 00 00 50 57 53 ff 15 [0-4] 50 ff 54 [0-2] 8b f0 3b f3 74}  //weight: 1, accuracy: Low
        $x_1_3 = {57 56 83 e7 0f 83 e6 0f 3b fe 5e 5f}  //weight: 1, accuracy: High
        $x_1_4 = {8b f8 53 8d [0-12] c6 [0-3] 74 c6 [0-3] 61 c6 [0-3] 73 c6 [0-3] 6b c6 [0-3] 6d c6 [0-3] 67 c6 [0-3] 72 c6 [0-3] 2e c6 [0-3] 65 c6 [0-3] 78 c6 [0-3] 65 88 [0-3] ff}  //weight: 1, accuracy: Low
        $x_1_5 = "UnhookWindowsHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GG_2147743292_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GG!MTB"
        threat_id = "2147743292"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 06 8b 4d [0-2] 5f 5e 64 [0-2] 00 00 00 00 5b c9 c2}  //weight: 1, accuracy: Low
        $x_1_2 = {6a ff 50 64 [0-2] 00 00 00 00 50 8b 44 [0-2] 64 [0-2] 00 00 00 00 89 6c [0-2] 8d 6c [0-2] 50 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {57 53 ff 15 [0-4] 8b f8 53 [0-12] c6 [0-3] 74 c6 [0-3] 61 c6 [0-3] 73 c6 [0-3] 6b c6 [0-3] 6d c6 [0-3] 67 c6 [0-3] 72 c6 [0-3] 2e c6 [0-3] 65 c6 [0-3] 78 c6 [0-3] 65 88 [0-3] ff}  //weight: 1, accuracy: Low
        $x_1_4 = {8a 03 88 45 [0-2] ff 15 [0-4] 0f b6 [0-2] 0f b6 [0-2] 03 c1 8b ce 99 f7 f9 8a 84 [0-6] 32 45 [0-2] 88 03 43 ff 4d [0-2] 75}  //weight: 1, accuracy: Low
        $x_1_5 = "UnhookWindowsHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GG_2147743292_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GG!MTB"
        threat_id = "2147743292"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f4 64 89 0d 00 00 00 00 59 5f 5f 5e 5b 8b e5 5d 51 c3 8b 4d [0-2] 33 cd e8 [0-4] e9}  //weight: 1, accuracy: Low
        $x_1_2 = {64 a1 00 00 00 00 50 83 ec [0-2] a1 [0-4] 33 c4 89 44 [0-2] 53 55 56 57 a1 [0-4] 33 c4 50 8d 44 [0-2] 64 [0-1] 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {53 8d 4c 24 [0-3] 51 [0-7] c6 [0-3] 56 [0-3] c6 [0-3] 69 [0-3] c6 [0-3] 72 [0-3] c6 [0-3] 74 [0-3] c6 [0-3] 61 [0-3] 88 [0-3] c6 [0-3] 41 [0-3] 88 [0-3] 88 [0-3] c6 [0-3] 6f [0-3] c6 [0-3] 63 [0-3] c6 [0-3] 45 [0-3] c6 [0-3] 78 [0-3] c6 [0-3] 4e [0-3] c6 [0-3] 6d [0-3] c6 [0-3] 61 [0-3] 88}  //weight: 1, accuracy: Low
        $x_1_4 = "UnhookWindowsHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BD_2147743296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BD!MTB"
        threat_id = "2147743296"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 8b f2 0b ca f7 d0 f7 d6 0b c6 5e 23 c1 c3}  //weight: 1, accuracy: High
        $x_1_2 = {88 03 8b 44 24 ?? 83 c4 08 43 48 89 5c 24 ?? 89 44 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BD_2147743296_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BD!MTB"
        threat_id = "2147743296"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 5f 33 00 00 85 c0 74 42 8b 4d f8 3b 0d ?? ?? ?? ?? 72 02 eb 35 8b 75 f8 03 75 f0 8b 7d f8 03 7d f0 68 19 10 00 00 8b 15 ?? ?? ?? ?? 52 ff 15 ?? ?? ?? ?? 03 45 fc 8b 4d f4 8a 14 31 88 14 38 8b 45 f8 83 c0 01 89 45 f8 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_HB_2147743328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.HB"
        threat_id = "2147743328"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OXxqa3MkT0JHc2tMYWl0WWdIWlp0fVFraT94RnVQYjlWMQ" ascii //weight: 1
        $x_1_2 = "xtHgwKE|KN%ILM?Z0cG@z*#b84R23T6HF8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BE_2147743349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BE!MTB"
        threat_id = "2147743349"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d0 8a cb f6 d1 0a d8 8b 44 24 ?? f6 d2 0a ca 22 cb 88 08 40 83 6c 24 ?? 01 89 44 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BE_2147743349_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BE!MTB"
        threat_id = "2147743349"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 5f 33 00 00 85 c0 74 ?? 8b 4d f8 3b 0d ?? ?? ?? ?? 72 ?? eb ?? 8b 55 f8 03 55 f0 8b 45 f8 03 45 f0 8b 4d fc 8b 75 f4 8a 14 16 88 14 01 8b 45 f8 83 c0 01 89 45 f8 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_HC_2147743370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.HC"
        threat_id = "2147743370"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 c1 8b c8 c1 e1 1f c1 f9 1f 8b f0 c1 e6 1d c1 fe 1f 81 e6 19 c4 6d 07 81 e1 96 30 07 77 33 ce 8b f0 c1 e6 19 c1 fe 1f 81 e6 90 41 dc 76 33 ce 8b f0 c1 e6 1a c1 fe 1f 81 e6 c8 20 6e 3b 33 ce 8b f0 c1 e6 1b c1 fe 1f 81 e6 64 10 b7 1d 33 ce 8b f0 c1 e6 1c c1 fe 1f 81 e6 32 88 db 0e 33 ce 8b f0 c1 ee 08 33 ce 8b f0 c1 e6 18 c1 e0 1e c1 fe 1f c1 f8 1f 81 e6 20 83 b8 ed 33 ce 25 2c 61 0e ee}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_HD_2147743455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.HD!MSR"
        threat_id = "2147743455"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Trjimklo\\Release\\TRJIMKLO.pdb" ascii //weight: 1
        $x_1_2 = "2003\\Efential\\Release\\EFENTIAL.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_SP_2147743476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SP!MSR"
        threat_id = "2147743476"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fAkeLJmrVGqoB3HFQ" wide //weight: 1
        $x_1_2 = "blitz_textures/top2.tga" ascii //weight: 1
        $x_1_3 = "Program Will Now Close" ascii //weight: 1
        $x_1_4 = "SetForegroundWindow" ascii //weight: 1
        $x_1_5 = "SHUTDOWN ERROR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_SP_2147743476_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SP!MSR"
        threat_id = "2147743476"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "666666UdetailsgKinto25browserw" wide //weight: 1
        $x_1_2 = "firstdickheadsupport" wide //weight: 1
        $x_1_3 = "releasesvacancyaddressbrowser" wide //weight: 1
        $x_1_4 = "BzCKyZ-isoTDiDbY.KbMjQw.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Emotet_ST_2147743487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.ST!MTB"
        threat_id = "2147743487"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 f8 33 c0 42 81 e2 [0-4] 89 55 f8 8b 4d f8 8a 84 0d e4 fe ff ff 89 45 f0 33 c0 8b 55 f4 03 55 f0 81 e2 ff 00 00 00 89 55 f4 8b 4d f4 8a 84 0d e4 fe ff ff 89 45 ec 8b 4d f8 8a 55 ec 88 94 0d e4 fe ff ff 8b 55 f4 8a 45 f0 88 84 15 e4 fe ff ff 33 c0 8a 4d f0 02 4d ec 8a c1 8b 4d 08 8a 94 05 e4 fe ff ff 8b 45 fc 30 14 01 ff 45 fc 8b 55 fc 3b 55 0c 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c3 bf 0a 00 00 00 99 f7 ff 80 c2 ?? 33 c0 8a c1 88 14 06 8b c3 bb 0a 00 00 00 99 f7 fb 8b d8 49 85 db 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_R_2147743488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.R!MTB"
        threat_id = "2147743488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 6a 40 68 00 30 00 00 56 6a 00 55 ff d7 8b 54 24 10 8b f8 56 52 57 ff d3 8d 44 24 28 6a 26 50 56 57 ff 54 24 34 83 c4 1c ff d7 5f 5e 5d 33 c0 5b 83 c4 34 c3}  //weight: 1, accuracy: High
        $x_1_2 = {8b 74 24 14 6a 00 6a 00 8b f8 8b 44 24 24 56 6a 00 6a 01 50 53 ff d7 85 c0 75}  //weight: 1, accuracy: High
        $x_1_3 = "CryptStringToBinaryA" ascii //weight: 1
        $x_1_4 = "Pablo Software Solutions" ascii //weight: 1
        $x_1_5 = "CCloudsCtrl Example" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_R_2147743488_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.R!MTB"
        threat_id = "2147743488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AUOEWIZUFE" ascii //weight: 1
        $x_2_2 = "SICUHHTJIN" wide //weight: 2
        $x_2_3 = "CgyOwsuhbS" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AR_2147743489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AR!MTB"
        threat_id = "2147743489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 45 17 59 8b 4d 10 43 ff 45 10 88 01 3b 1d ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 04 33 8b fa 33 d2 8a 0c 37 88 04 37 88 0c 33 0f b6 04 37}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AR_2147743489_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AR!MTB"
        threat_id = "2147743489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 14 8d 2c 3b 88 1c 28 8b c3 99 f7 7c 24 2c 8b 44 24 28 43 8a 14 02 88 55 00 3b de}  //weight: 1, accuracy: High
        $x_1_2 = {8b 54 24 18 0f b6 14 1a 8a 03 03 54 24 10 0f b6 c0 03 c2 33 d2 f7 f6 8a 03 43 83 6c 24 14 01 8b fa 8a 14 0f 88 04 0f 88 53 ff 89 7c 24 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AR_2147743489_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AR!MTB"
        threat_id = "2147743489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qepfjancikpk" ascii //weight: 1
        $x_1_2 = "lwcikmiltgjjvls" ascii //weight: 1
        $x_1_3 = "icsnbgshavbqpd" ascii //weight: 1
        $x_1_4 = "nbjdhmrlnnatveoo" ascii //weight: 1
        $x_10_5 = "ekernel32.dll" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_AR_2147743489_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AR!MTB"
        threat_id = "2147743489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f0 0f b6 14 38 8a 1f 03 55 fc 0f b6 c3 03 c2 33 d2 f7 f1 8d 04 32 89 55 fc 8a 10 88 18 88 17 47 ff 4d f4}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 14 2b 8a 03 03 54 24 10 0f b6 c0 03 c2 33 d2 f7 f1 8a 03 47 43 8a 0c 32 88 04 32 88 4b ff 8b 0d ?? ?? ?? ?? 3b f9 89 54 24 10}  //weight: 1, accuracy: Low
        $x_2_3 = {8a 0c 37 8b da 8a 04 33 88 0c 33 88 04 37 0f b6 14 33 0f b6 c0 03 c2 33 d2 f7 35 ?? ?? ?? ?? 89 54 24 14}  //weight: 2, accuracy: Low
        $x_2_4 = "TdfdgfsQrcgxgc" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_AR_2147743489_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AR!MTB"
        threat_id = "2147743489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 f7 f1 8a 03 47 43 8a 0c 32 88 04 32 88 4b ff 8b 0d ?? ?? ?? ?? 3b f9 89 54 24 10}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 24 8b 4c 24 14 8a 14 01 8b 4c 24 18 32 14 31 40 88 50 ff 89 44 24 24 ff 4c 24 10}  //weight: 1, accuracy: High
        $x_1_3 = {8b 44 24 10 8d 34 3b 88 1c 30 8b c3 99 f7 7c 24 28 8b 44 24 24 83 c3 01 81 fb e1 18 00 00 8a 14 02 88 16}  //weight: 1, accuracy: High
        $x_1_4 = {8a 14 0f 8a 04 0e 88 14 0e 88 04 0f 0f b6 14 0e 0f b6 c0 03 c2 33 d2 f7 f5 0f b6 04 0a 8b 54 24 14 32 44 1a ff 83 6c 24 20 01 88 43 ff}  //weight: 1, accuracy: High
        $x_1_5 = "lhxXfY9mIrDZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Emotet_HC_2147743551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.HC!MSR"
        threat_id = "2147743551"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 e9 59 11 00 00 89 0d cc 5f 44 00 8b 0d cc 5f 44 00 81 c1 59 11 00 00 a1 d0 5f 44 00 a3 d4 5f 44 00 b8 c9 ee 06 00 b8 c9 ee 06}  //weight: 1, accuracy: High
        $x_1_2 = {b8 c9 ee 06 00 b8 c9 ee 06 00 b8 c9 ee 06 00 b8 c9 ee 06 00 a1 d4 5f 44 00 31 0d d4 5f 44 00 8b ff c7 05 d0 5f 44 00 00 00 00 00 a1 d4 5f 44 00 01 05 d0 5f 44 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DHE_2147743552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DHE!MTB"
        threat_id = "2147743552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 14 53 8d 34 07 e8 ?? ?? ?? ?? 59 33 d2 8b c8 8b c7 f7 f1 8a 04 1a 30 06 47 3b 7c 24 18 75 d4}  //weight: 2, accuracy: Low
        $x_1_2 = "VirtualAlloc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RO_2147743557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RO!MSR"
        threat_id = "2147743557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b c6 c1 e0 1f c1 f8 1f 8b ce c1 e1 1d c1 f9 1f 81 e1 19 c4 6d 07 25 96 30 07 77 33 c1 8b ce c1 e1 19 c1 f9 1f 81 e1 90 41 dc 76 33 c1 8b ce c1 e1 1a c1 f9 1f 81 e1 c8 20 6e 3b 33 c1 8b ce c1 e1 1b c1 f9 1f 81 e1 64 10 b7 1d 33 c1 8b ce c1 e1 1c c1 f9 1f 81 e1 32 88 db 0e 33 c1 8b ce c1 e9 08 33 c1 8b ce c1 e1 18 c1 e6 1e c1 f9 1f c1 fe 1f 81 e1 20 83 b8 ed 33 c1 81 e6 2c 61 0e ee 33 f0 47 0f b6 07 85 c0 0f 85}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RN_2147743558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RN!MSR"
        threat_id = "2147743558"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b c6 c1 e0 1f c1 f8 1f 8b ce c1 e1 1d c1 f9 1f 81 e1 19 c4 6d 07 25 96 30 07 77 33 c1 8b d6 c1 e2 19 c1 fa 1f 8b ce c1 e1 1a c1 f9 1f 81 e2 90 41 dc 76 33 c2 81 e1 c8 20 6e 3b 33 c1 8b d6 c1 e2 1b 8b ce c1 e1 1c c1 fa 1f c1 f9 1f 81 e2 64 10 b7 1d 33 c2 81 e1 32 88 db 0e 33 c1 8b ce 8b d6 c1 e1 18 c1 e6 1e c1 ea 08 c1 f9 1f 33 c2 c1 fe 1f 81 e1 20 83 b8 ed 33 c1 81 e6 2c 61 0e ee 47 33 f0 0f b6 07 85 c0 0f 85}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RP_2147743559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RP!MSR"
        threat_id = "2147743559"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 f8 33 45 d4 89 45 f8 8b 45 f8 c1 e0 1f c1 f8 1f 89 c2 81 e2 96 30 07 77 8b 45 f8 c1 e0 1e c1 f8 1f 25 2c 61 0e ee 31 c2 8b 45 f8 c1 e0 1d c1 f8 1f 25 19 c4 6d 07 31 c2 8b 45 f8 c1 e0 1c c1 f8 1f 25 32 88 db 0e 31 c2 8b 45 f8 c1 e0 1b c1 f8 1f 25 64 10 b7 1d 31 c2 8b 45 f8 c1 e0 1a c1 f8 1f 25 c8 20 6e 3b 31 c2 8b 45 f8 c1 e0 19 c1 f8 1f 25 90 41 dc 76 31 c2 8b 45 f8 c1 e0 18 c1 f8 1f 25 20 83 b8 ed 31 d0 89 45 d0 8b 45 f8 c1 e8 08 33 45 d0 89 45 f8 ff 45 fc 8b 55 fc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RP_2147743559_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RP!MSR"
        threat_id = "2147743559"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "c:\\Users\\User\\Desktop\\2008\\Win32_-_IE1201458192002\\Release\\IE_MENUBAR.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DHA_2147743606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DHA!MTB"
        threat_id = "2147743606"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 81 e1 ff 00 00 00 8b 3c 8d ?? ?? ?? ?? 03 c7 25 ff 00 00 00 8a 14 85 ?? ?? ?? ?? 89 3c 85 70 a8 42 00 0f b6 d2 89 14 8d ?? ?? ?? ?? 8b 3c 85 ?? ?? ?? ?? 03 fa 81 e7 ff 00 00 00 0f b6 14 bd ?? ?? ?? ?? 30 14 2e 83 ee 01 79 b4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DS_2147743650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DS!MTB"
        threat_id = "2147743650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 33 33 d2 69 c8 ?? ?? 00 00 0f b6 06 c7 45 fc ?? 00 00 00 49 0f af c8 8b c3 f7 75 fc 8a 44 15 ?? 30 84 19 ?? ?? ?? ?? 43 81 fb ?? ?? 00 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RX_2147743651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RX!MSR"
        threat_id = "2147743651"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e0 1f c1 f8 1f 8b ce c1 e1 1d c1 f9 1f 81 e1 19 c4 6d 07 25 96 30 07 77 33 c1}  //weight: 1, accuracy: High
        $x_1_2 = {81 e1 c8 20 6e 3b 33 c1}  //weight: 1, accuracy: High
        $x_1_3 = {81 e1 32 88 db 0e 33 c1}  //weight: 1, accuracy: High
        $x_1_4 = {81 e1 20 83 b8 ed 33 c1 81 e6 2c 61 0e ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_MS_2147743672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.MS!MTB"
        threat_id = "2147743672"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 02 5f 5d c3 21 00 33 c1 ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 05 ?? ?? ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_MS_2147743672_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.MS!MTB"
        threat_id = "2147743672"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 1b cb 06 00 b8 1b cb 06 00 b8 1b cb 06 00 b8 1b cb 06 00 b8 1b cb 06 00 b8 1b cb 06 00 b8 1b cb 06 00 b8 1b cb 06 00 b8 1b cb 06 00 b8 1b cb 06 00 a1 ?? ?? ?? ?? 33 c1 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GA_2147743677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GA!MTB"
        threat_id = "2147743677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c0 04 0f af 05 ?? ?? ?? ?? 03 d0 8d 47 01 0f af c7 2b d0 8b 44 24 ?? 2b d3 2b d1 8a 0c 32 30 08 8b 44 24 ?? 40 89 44 24 ?? 3b 44 24 ?? 0f 82}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GA_2147743677_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GA!MTB"
        threat_id = "2147743677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 c6 01 00 8d 49 01 83 ee 01 75}  //weight: 1, accuracy: High
        $x_1_2 = {03 c1 83 e0 ?? 0f b6 44 05 ?? 32 42 ?? 88 41 ?? 8b 45 ?? 03 c1 83 e0 ?? 0f b6 44 05 ?? 32 42 ?? 88 41 ?? 8d 04 17 83 c1 04 3d 00 32 02 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GA_2147743677_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GA!MTB"
        threat_id = "2147743677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\{aa5b6a80-b834-11d0-932f-00a0c90dcaa9}" ascii //weight: 1
        $x_1_2 = {8b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02 5f 5d c3 60 00 b8 ?? ?? ?? ?? b8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 31}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c0 01 89 45 f8 eb 40 00 74 ?? 8b 4d ?? 3b 0d ?? ?? ?? ?? 72 [0-3] 8b 55 ?? 03 55 ?? 8b 45 ?? 03 45 ?? 8b 4d ?? 8b 75 ?? 8a ?? ?? 88 ?? ?? 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GA_2147743677_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GA!MTB"
        threat_id = "2147743677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 06 8b 4d [0-2] 5f 5e 64 [0-2] 00 00 00 00 5b c9 c2}  //weight: 1, accuracy: Low
        $x_1_2 = {6a ff 50 64 [0-2] 00 00 00 00 50 8b 44 [0-2] 64 [0-2] 00 00 00 00 89 6c [0-2] 8d 6c [0-2] 50 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {66 8b 06 66 f7 d8 1b c0 23 c6 5e 5f 5b c3}  //weight: 1, accuracy: High
        $x_1_4 = {50 89 7c 24 [0-2] c6 [0-3] 74 c6 [0-3] 61 c6 [0-3] 73 c6 [0-3] 6b c6 [0-3] 6d c6 [0-3] 67 c6 [0-3] 72 c6 [0-3] 2e c6 [0-3] 65 c6 [0-3] 78 c6 [0-3] 65 88 5c [0-2] ff d5}  //weight: 1, accuracy: Low
        $x_1_5 = "UnhookWindowsHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PG_2147743680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PG!MTB"
        threat_id = "2147743680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {8b 45 fc 33 d2 f7 f1 8b 45 08 0f b7 0c 50 8b 55 0c 03 55 fc 0f b6 02 33 c1 8b 4d 0c 03 4d fc 88 01 eb}  //weight: 20, accuracy: High
        $x_1_2 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 10 74}  //weight: 1, accuracy: High
        $x_21_3 = {59 8b f0 59 6a ?? 8b ce e8 ?? ?? ?? ?? 8b ce e8 ?? ?? ?? ?? 8b 44 24 ?? 53 8d 34 07 e8 ?? ?? ?? ?? 59 33 d2 8b c8 8b c7 f7 f1 8a 04 53 30 06 47 3b 7c 24 ?? 75 0f 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8}  //weight: 21, accuracy: Low
        $x_21_4 = {53 8d 34 07 ff 15 ?? ?? ?? ?? 8b c8 8b c7 33 d2 83 c4 10 f7 f1 8a 04 53 30 06 47 3b 7c 24 ?? 75 1c 00 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b 44 24}  //weight: 21, accuracy: Low
        $x_20_5 = {2b c2 d1 f8 8b c8 33 d2 8b c7 f7 f1 [0-5] 47 8a 14 56 30 54 ?? ff 3b (7c|7d) [0-2] 0f 85 ?? ?? ff ff}  //weight: 20, accuracy: Low
        $x_20_6 = {2b c2 d1 f8 8b c8 33 d2 8b c5 f7 f1 8b 44 24 ?? 83 c5 01 8a 14 56 30 54 28 ff 3b 6c 24 ?? 0f 85}  //weight: 20, accuracy: Low
        $x_1_7 = {6a 00 50 e8 ?? ?? ?? ?? 8b (74|75) [0-2] 8b c6 8d 50 02 [0-10] 66 8b 08 83 c0 02 66 85 c9 75}  //weight: 1, accuracy: Low
        $x_21_8 = {8b c8 ff 15 ?? ?? ?? ?? 8b c3 8d 50 02 eb ?? 8d 9b 00 00 00 00 66 8b 08 83 c0 02 66 85 c9 75 f5 2b c2 d1 f8 8b c8 33 d2 8b c6 f7 f1 46 8a 14 53 30 54 3e ff 3b 75 08 75}  //weight: 21, accuracy: Low
        $x_21_9 = {8b c3 8d 70 02 66 8b 10 83 c0 02 66 85 d2 75 f5 2b c6 d1 f8 8b f0 8b c1 33 d2 f7 f6 (41|83) 8a 04 53 30 44 39 ff 3b cd 75}  //weight: 21, accuracy: Low
        $x_21_10 = {33 f6 85 ed 74 ?? 53 8b 5c 24 ?? 57 8b 7c 24 ?? 53 e8 ?? ?? ?? ?? 8b c8 33 d2 8b c6 f7 f1 8a 04 3e 83 c4 04 8a 14 53 32 c2 88 04 3e 46 3b f5 75}  //weight: 21, accuracy: Low
        $x_21_11 = {8b c3 8d 70 02 eb 03 8d 49 00 66 8b 10 83 c0 02 66 85 d2 75 f5 2b c6 d1 f8 8b f0 8b c1 33 d2 f7 f6 83 c1 01 8a 04 53 30 44 39 ff 3b cd 75 d1}  //weight: 21, accuracy: High
        $x_21_12 = {8b c5 8d 50 02 8d 49 00 66 8b 08 83 c0 02 66 85 c9 75 f5 2b c2 d1 f8 8b c8 8b c7 33 d2 f7 f1 47 8a 44 55 00 30 44 1f ff 3b 7c 24 1c 0f 85}  //weight: 21, accuracy: High
        $x_21_13 = {8b 44 24 20 83 c4 0c 53 8d 34 07 e8 ?? ?? ?? ?? 8b c8 33 d2 8b c7 f7 f1 8a 04 53 30 06 47 3b 7c 24 18 75 c7 15 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8}  //weight: 21, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            ((1 of ($x_21_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_SR_2147743719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SR!MTB"
        threat_id = "2147743719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 53 56 57 [0-32] 74 ?? 57 e8 ?? ?? ?? ?? 59 50 8b c3 5a 8b ca 33 d2 f7 f1 8a 04 57 30 06 43 46 [0-6] 3b d8 75 e1}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 53 56 57 [0-32] 74 ?? 56 e8 ?? ?? ?? ?? 59 50 8b c3 5a 8b ca 33 d2 f7 f1 8a 04 56 30 04 1f 43 3b 5d 10 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PDSK_2147743751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PDSK!MTB"
        threat_id = "2147743751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 fc 33 d2 f7 f1 8b 45 08 0f b7 0c 50 8b 55 0c 03 55 fc 0f b6 02 33 c1 8b 4d 0c 03 4d fc 88 01 eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RE_2147743756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RE!MSR"
        threat_id = "2147743756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "c:\\Documents and Settings\\Administrator\\My Documents\\Visual Studio Projects\\EASZZCDFR\\Release\\EASZZCDFR.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_B_2147743800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.B!MTB"
        threat_id = "2147743800"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Decrypt" ascii //weight: 1
        $x_1_2 = {8b c3 8d 70 02 eb 03 ?? ?? ?? 66 8b 10 83 c0 02 66 85 d2 75 f5 2b c6 d1 f8 8b f0 8b c1 33 d2 f7 f6 41 8a 04 53 30 44 39 ff 3b cd 75 d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_C_2147743801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.C!MTB"
        threat_id = "2147743801"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 53 8b 5d 10 56 33 f6 85 db 74 2d 57 8b 7d 08 8b cf 8d 51 02 66 8b 01 83 c1 02 66 85 c0 75 f5 2b ca 8b c6 d1 f9 33 d2 f7 f1 8b 4d 0c 8a 04 57 30 04 0e 46 3b f3 75 d8 5f 5e 5b 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 56 33 f6 39 75 10 74 25 53 8b 5d 08 57 8b 7d 0c 53 e8 ?? ?? 00 00 59 8b c8 33 d2 8b c6 f7 f1 8a 04 53 30 04 3e 46 3b 75 10 75 e5 5f 5b 5e 5d c3}  //weight: 1, accuracy: Low
        $x_1_3 = {56 33 f6 39 74 24 10 74 22 57 8b 44 24 10 6a ?? 33 d2 5f 8d 0c 06 8b c6 f7 f7 8b 44 24 0c 8a 04 50 30 01 46 3b 74 24 14 75 e0 5f 5e c3}  //weight: 1, accuracy: Low
        $x_1_4 = {00 00 83 c4 08 8b c8 e8 ?? ?? 00 00 8b 45 fc 33 d2 b9 ?? 00 00 00 f7 f1 8b 45 0c 03 45 fc 8b 4d 08 8a 00 32 04 51 8b 4d 0c 03 4d fc 88 01 e9 ?? ?? ff ff 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 45 0c 8b 4d fc ff 75 08 8d 1c 01 e8 ?? ?? 00 00 59 33 d2 8b c8 8b 45 fc f7 f1 8b 45 08 8a 04 50 30 03 ff 45 fc 8b 45 fc 3b 45 10 75 ?? 5e 5b 5f c9 c3}  //weight: 1, accuracy: Low
        $x_1_6 = {6a 00 ff d6 8b c5 8d 50 02 8d 49 00 66 8b 08 83 c0 02 66 85 c9 75 f5 2b c2 d1 f8 8b c8 8b c7 33 d2 f7 f1 83 c7 01 8a 44 55 00 30 44 1f ff 3b 7c 24 1c 0f 85 74 ff ff ff 5e 5d 5b 5f c3}  //weight: 1, accuracy: High
        $x_1_7 = {ff d6 8b 44 24 18 8b 4c 24 14 8d 1c 28 e8 ?? ?? ff ff 8b c8 33 d2 8b c5 f7 f1 8b 44 24 14 8a 04 50 30 03 45 81 fd ?? ?? ?? ?? 75 ?? 5f 5e 5d 5b c3}  //weight: 1, accuracy: Low
        $x_1_8 = {8b 45 0c 8b 4d fc ff 75 08 8d 1c 01 e8 ?? ?? ff ff 8b c8 8b 45 fc 33 d2 f7 f1 8b 45 08 8a 04 50 30 03 ff 45 fc 8b 45 fc 3b 45 10 75 ?? 5e 5b 5f c9 c3}  //weight: 1, accuracy: Low
        $x_1_9 = {6a 00 6a 00 ff 15 ?? ?? ?? 00 8b 55 08 52 e8 ?? ?? 00 00 83 c4 04 8b c8 8b 45 fc 33 d2 f7 f1 8b 45 08 0f b7 0c 50 8b 55 0c 03 55 fc 0f b6 02 33 c1 8b 4d 0c 03 4d fc 88 01 e9 ?? ?? ff ff 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_10 = {57 33 ff 39 7c 24 10 74 29 53 8b 5c 24 0c 56 8b 44 24 14 53 8d 34 07 e8 ?? ?? ?? ?? 8b c8 8b c7 33 d2 f7 f1 8a 04 53 30 06 47 3b 7c 24 18 75 df 5e 5b 5f c3}  //weight: 1, accuracy: Low
        $x_1_11 = {ff d7 8b 45 0c 8b 4d fc ff 75 08 8d 1c 01 e8 ?? ?? ?? ?? 8b c8 8b 45 fc 33 d2 f7 f1 8b 45 08 8a 04 50 30 03 ff 45 fc 8b 45 fc 3b 45 10 0f 85 ?? ?? ff ff 5f 5b 5e c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_D_2147743802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.D!MTB"
        threat_id = "2147743802"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 4a 0d ce 09 [0-16] e8 ?? ?? ff ff [0-16] e8 ?? ?? ff ff 00 08 6a 40 68 00 10 00 00 [0-16] ff d0 [0-16] e8 ?? ?? 00 00 [0-16] 68 91 01 00 00 50 e8 ?? ?? ff ff 83 c4 18 83 78 ?? 08 72}  //weight: 1, accuracy: Low
        $x_1_2 = {68 4a 0d ce 09 [0-16] e8 ?? ?? ff ff [0-16] e8 ?? ?? ff ff 00 08 6a 40 68 00 10 00 00 [0-16] ff 55 [0-16] e8 ?? ?? 00 00 [0-16] 68 91 01 00 00 50 e8 ?? ?? ff ff 83 c4 18 83 78 ?? 08 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DHB_2147743826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DHB!MTB"
        threat_id = "2147743826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 04 24 b9 d6 48 55 41 8b 54 24 18 8b 74 24 14 81 ca ea 99 e8 54 89 54 24 18 29 f1 8b 54 24 04 89 54 24 24 8b 74 24 0c 8a 1c 06 8b 7c 24 08 88 1c 07 01 c8 8b 4c 24 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DHC_2147743827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DHC!MTB"
        threat_id = "2147743827"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b1 a6 8a 54 24 2f 80 f2 61 88 54 24 2f 8b 74 24 14 01 f6 89 74 24 28 2a 4c 24 2f 8b 74 24 04 8a 14 06 88 4c 24 2f 8b 7c 24 0c 88 14 07}  //weight: 1, accuracy: High
        $x_1_2 = "self.exe" ascii //weight: 1
        $x_1_3 = "d:\\usr\\rod\\rnr.pdb" ascii //weight: 1
        $x_1_4 = "hackersalthoughZinrFdGoogleYD" wide //weight: 1
        $x_1_5 = "theremalware),g" wide //weight: 1
        $x_1_6 = "jofy4was" wide //weight: 1
        $x_1_7 = "NwDGqcNSirbrowser" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Emotet_DHD_2147743828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DHD!MTB"
        threat_id = "2147743828"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 d8 8b 5c 24 14 81 c3 47 ae ff ff 66 89 d9 21 f8 66 89 4c 24 56 8b 7c 24 38 8a 04 07 8b 5c 24 1c 8b 54 24 0c 8a 24 13 c6 44 24 55 e8 30 e0 8b 54 24 18 8b 7c 24 0c 88 04 3a}  //weight: 1, accuracy: High
        $x_1_2 = {66 8b 44 24 78 66 b9 bd 61 66 29 c1 8b 54 24 38 66 89 0a 8b 54 24 2c 81 f2 48 61 4b 6b [0-22] c7 42 3c 38 01 00 00 8b 54 24 38 66 8b 44 24 1a 66 0d aa 22 66 89 44 24 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_ML_2147743829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.ML!MTB"
        threat_id = "2147743829"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 49 00 66 8b 10 83 c0 02 66 85 d2 75 ?? 2b c6 d1 f8 8b f0 8b c1 33 d2 f7 f6 41 8a 04 53 30 44 39 ff 3b cd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PA_2147743888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PA!MSR"
        threat_id = "2147743888"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\MORENA\\Release\\MORENA.pdb" ascii //weight: 1
        $x_1_2 = "MORENA.exe" ascii //weight: 1
        $x_1_3 = {66 0f b6 32 8b cf 66 d3 e6 42 66 f7 d6 0f b7 ce 88 28 88 48 ?? 03 45 ?? ff 4d ?? 75}  //weight: 1, accuracy: Low
        $x_1_4 = {2a c3 88 07 47 ff 4d [0-4] 8a 02 42 3a c3 7d [0-4] eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BZ_2147743893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BZ!MTB"
        threat_id = "2147743893"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d9 8a d0 0a c1 f6 d2 f6 d3 0a d3 22 d0 8b 44 24 ?? 88 16 46 48 89 74 24 ?? 89 44 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BZ_2147743893_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BZ!MTB"
        threat_id = "2147743893"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 89 45 fc 8b 4d fc 3b 4d 10 74 ?? 8b 55 08 52 e8 ?? ?? ?? ?? 83 c4 04 8b c8 8b 45 fc 33 d2 f7 f1 8b 45 0c 03 45 fc 8b 4d 08 8a 00 32 04 51 8b 4d 0c 03 4d fc 88 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PVD_2147743911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PVD!MTB"
        threat_id = "2147743911"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 44 24 14 53 8d 34 07 e8 ?? ?? ?? ?? 59 8b c8 33 d2 8b c7 f7 f1 8a 04 53 30 06 47 3b 7c 24 18 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BY_2147743943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BY!MTB"
        threat_id = "2147743943"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 10 6a 22 33 d2 5f 8d 0c 06 8b c6 f7 f7 8b 44 24 0c 8a 04 50 30 01 46 3b 74 24 14 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BY_2147743943_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BY!MTB"
        threat_id = "2147743943"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a c8 f6 d1 f6 d2 0a ca 0a 44 24 ?? 22 c8 8b 44 24 ?? 88 08 40 89 44 24 ?? ff 4c 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DHF_2147744019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DHF!MTB"
        threat_id = "2147744019"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 0f 8d 7f 04 33 ca 0f b6 c1 66 89 06 8b c1 c1 e8 08 8d 76 08 0f b6 c0 66 89 46 fa c1 e9 10 0f b6 c1 66 89 46 fc c1 e9 08 0f b6 c1 66 89 46 fe 8b 45 fc 40 89 45 fc 3b c3 72 c5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DHH_2147744025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DHH!MTB"
        threat_id = "2147744025"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 16 8b 54 24 3c 8a 24 0a 28 c4 [0-27] 88 24 0e 8a 64 24 13 30 e0 8b 7c 24 0c 88 44 3c 50}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 0c 02 8b 75 ec 81 ce 0c f7 e1 00 89 75 ec 66 8b 7d ea 66 89 7d ea 8b 75 dc 88 0c 06 8a 4d f3 8a 6d f3 83 c0 01 08 e9 88 4d f3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_SR_2147744057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SR!MSR"
        threat_id = "2147744057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {59 8b c8 8b 45 fc 33 d2 f7 f1 8b 45 08 8a 04 50 30 03 ff 45 fc 8b 45 fc 3b 45 10 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_SR_2147744057_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SR!MSR"
        threat_id = "2147744057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "permission denied" ascii //weight: 1
        $x_1_2 = "sectioncity\\womanespecially\\farmStudy\\howLess\\CardCase\\abouttotal\\CompareEdgeMother.pdb" ascii //weight: 1
        $x_1_3 = "Boarnoun.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RF_2147744067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RF!MSR"
        threat_id = "2147744067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 c1 e0 07 c1 ee 19 0b f0 0f be c1 8a 4a 01 33 c6 42 84 c9 75 e9}  //weight: 1, accuracy: High
        $x_1_2 = {53 8b 5c 24 10 57 8b 7c 24 18 53 e8 ?? ?? 00 00 8b c8 33 d2 8b c6 f7 f1 8a 04 3e 83 c4 04 8a 14 53 32 c2 88 04 3e 46 3b f5 75 df}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PVDS_2147744123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PVDS!MTB"
        threat_id = "2147744123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 0c 03 45 fc 8b 4d 08 8a 00 32 04 51 8b 4d 0c 03 4d fc 88 01 e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_SQ_2147744159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SQ!MSR"
        threat_id = "2147744159"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c8 8b c7 33 d2 83 c4 04 f7 f1 8a 04 1f 8a 54 55 00 32 c2 88 04 1f 8b 44 24 1c 47 3b f8 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_SQ_2147744159_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SQ!MSR"
        threat_id = "2147744159"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zcsdASkxxFDzcsThU" ascii //weight: 1
        $x_1_2 = "User\\Desktop\\2008\\A_3D_clock159587622003\\Release\\3D RPG.pdb" ascii //weight: 1
        $x_1_3 = "SHUTDOWN" ascii //weight: 1
        $x_1_4 = "msg_exit" ascii //weight: 1
        $x_1_5 = "dllonexit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_SA_2147744163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SA!MSR"
        threat_id = "2147744163"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\Users\\User\\Desktop\\2003\\calcdriv\\Release\\calcdriv.pdb" ascii //weight: 1
        $x_1_2 = "calcdriv.exe" ascii //weight: 1
        $x_1_3 = "Sleep" ascii //weight: 1
        $x_1_4 = "mfccalc.calculator" wide //weight: 1
        $x_1_5 = "Application Data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_SA_2147744163_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SA!MSR"
        threat_id = "2147744163"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 66 78 43 6f 6e 74 72 6f 6c 42 61 72 ?? ?? 73}  //weight: 1, accuracy: Low
        $x_1_2 = {41 66 78 4d 44 49 46 72 61 6d 65 ?? ?? 73}  //weight: 1, accuracy: Low
        $x_1_3 = {41 66 78 46 72 61 6d 65 4f 72 56 69 65 77 ?? ?? 73}  //weight: 1, accuracy: Low
        $x_1_4 = "MFC Application" wide //weight: 1
        $x_1_5 = "CRYPT32.DLL" wide //weight: 1
        $x_1_6 = "CryptStringToBinaryA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BX_2147744183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BX!MTB"
        threat_id = "2147744183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c2 d1 f8 8b c8 8b c7 33 d2 f7 f1 47 8a 44 55 00 30 44 1f ff 3b 7c 24 1c 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {33 d2 8b c8 8b 45 fc f7 f1 8b 45 08 8a 04 50 30 03 ff 45 fc 8b 45 fc 3b 45 10 75}  //weight: 1, accuracy: High
        $x_1_3 = {8b c8 8b 45 fc 33 d2 f7 f1 8b 45 08 8a 04 50 30 03 ff 45 fc 8b 45 fc 3b 45 10}  //weight: 1, accuracy: High
        $x_1_4 = {8b c8 33 d2 8b c5 f7 f1 8b 44 24 14 8a 04 50 30 03 45 81 fd ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_5 = {33 d2 f7 f1 8b 45 08 0f b7 0c 50 8b 55 0c 03 55 fc 0f b6 02 33 c1 8b 4d 0c 03 4d fc 88 01 e9}  //weight: 1, accuracy: High
        $x_1_6 = {8b c8 8b c7 33 d2 f7 f1 8a 04 53 30 06 47 3b 7c 24 18 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_RU_2147744202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RU!MSR"
        threat_id = "2147744202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5c 24 0c 56 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 dc df ff ff 50 e8 04 df ff ff 8b 44 24 ?? 83 c4 ?? 53 8d 34 07 e8 f2 e0 ff ff 8b c8 33 d2 8b c7 f7 f1 8a 04 53 30 06 47 3b 7c 24 18 75 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_S_2147744210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.S!MSR"
        threat_id = "2147744210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "mfccalc.calculator" ascii //weight: 2
        $x_2_2 = "FUCK ESET" wide //weight: 2
        $x_1_3 = "%s\\shell\\print" ascii //weight: 1
        $x_1_4 = "EncryptData" ascii //weight: 1
        $x_1_5 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_6 = "CryptEncrypt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_OS_2147744219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.OS!MSR"
        threat_id = "2147744219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 ff d6 55 e8 6a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_E_2147744243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.E!MTB"
        threat_id = "2147744243"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 10 00 00 ff 75 0c 56 ff 55 c0 ff 75 0c 8b f8 ff 75 08 57 ff 55 e0 83 c4 0c ff 75 0c 8d 45 0c 50 57 56 53 56 ff 75 f4 ff 55 e4 f7 d8 1b c0 23 c7 5f 5e 5b c9 c3 ff 00 8d 45 f8 50 56 56 68 03 80 00 00 ff 75 fc ff 55 e8 85 c0 74}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 68 00 10 00 00 ff 75 0c 56 ff 55 c0 ff 75 0c 8b f8 ff 75 08 57 ff 55 e0 83 c4 0c 8d 45 0c ff 75 0c 50 57 56 53 56 ff 75 f4 ff 55 e4 f7 d8 1b c0 23 c7 5f 5e 5b c9 c3 ff 00 8d 45 f8 50 56 56 68 03 80 00 00 ff 75 fc ff 55 e8 85 c0 74}  //weight: 1, accuracy: Low
        $x_1_3 = "memcpy" wide //weight: 1
        $x_1_4 = "VirtualAlloc" wide //weight: 1
        $x_1_5 = "CryptEncrypt" wide //weight: 1
        $x_1_6 = "CryptAcquireContextW" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Emotet_HG_2147744254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.HG!MSR"
        threat_id = "2147744254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CJGtKmmbXBrgzxC" ascii //weight: 2
        $x_1_2 = "BINDSCRB.exe" ascii //weight: 1
        $x_2_3 = "VpcVxOAdCvvNNuq" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_SI_2147744256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SI!MSR"
        threat_id = "2147744256"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vbcgdfaszxddferqasw" wide //weight: 1
        $x_1_2 = "drop into window" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PH_2147744313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PH!MTB"
        threat_id = "2147744313"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 57 a1 ?? ?? ?? 00 a3 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 8b 11 89 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 2d 59 2f 00 00 a3 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 81 c1 59 2f 00 00 a1 ?? ?? ?? 00 a3 ?? ?? ?? 00 a1 ?? ?? ?? 00 31 0d ?? ?? ?? 00 8b ff c7 05 ?? ?? ?? 00 00 00 00 00 a1 ?? ?? ?? 00 01 05 ?? ?? ?? 00 8b ff 5f 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_ST_2147744338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.ST!MSR"
        threat_id = "2147744338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Open this document" wide //weight: 1
        $x_1_2 = "Replace%Select the entire documen" wide //weight: 1
        $x_1_3 = "Crypt" wide //weight: 1
        $x_1_4 = "&Neighbor" wide //weight: 1
        $x_1_5 = "B&eer" wide //weight: 1
        $x_1_6 = "Snap.Document" wide //weight: 1
        $x_1_7 = "SNAP.EXE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_HI_2147744379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.HI!MSR"
        threat_id = "2147744379"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\ProgramData\\cvxgdfade.sxcase" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DHG_2147744381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DHG!MTB"
        threat_id = "2147744381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 0c 7d 1a 8b 55 08 03 55 fc 0f be 1a e8 ?? ?? ?? ?? 33 d8 8b 45 08 03 45 fc 88 18 eb d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DHI_2147744382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DHI!MTB"
        threat_id = "2147744382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 c1 e8 10 88 06 46 8b cb c1 e9 08 88 0e 46 88 1e 33 db 46 88 5d ff}  //weight: 1, accuracy: High
        $x_1_2 = {8b f1 c1 ee 05 03 35 ?? ?? ?? ?? 8b f9 c1 e7 04 03 3d ?? ?? ?? ?? 33 f7 8d 3c 0a 33 f7 2b c6 8b f0 c1 ee 05 03 35 ?? ?? ?? ?? 8b f8 c1 e7 04 03 3d ?? ?? ?? ?? 33 f7 8d 3c 02 33 f7 2b ce 81 c2 ?? ?? ?? ?? 83 6d fc 01 75 b6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_IG_2147744395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.IG!MTB"
        threat_id = "2147744395"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d1 f8 48 c3 20 00 8b 44 ?? ?? 66 8b ?? 40 40 66 85 ?? 75 ?? 2b 44}  //weight: 1, accuracy: Low
        $x_1_2 = {55 6a 40 68 00 10 00 00 52 ?? ff d7 8b [0-3] 8b 74 [0-2] 8b ?? 8b ?? c1 e9 ?? 8b ?? f3 ?? 8b ?? 83 [0-4] f3 ?? 8d}  //weight: 1, accuracy: Low
        $x_10_3 = {55 8b 6c 24 [0-6] 74 ?? 53 8b [0-3] 57 8b [0-3] 53 [0-5] 8b c8 33 ?? 8b ?? f7 ?? 8a [0-2] 83 c4 04 8a [0-2] 03 01 01 01 32 30 33 ?? 88 [0-2] 46 3b f5 75}  //weight: 10, accuracy: Low
        $x_10_4 = {83 c4 04 8a [0-2] 03 01 01 01 32 30 33 ?? 88 [0-6] 03 01 01 01 45 47 46 3b [0-10] 5d c3 30 00 8b ?? 33 d2 8b ?? f7 f1 [0-4] 8a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_JG_2147744396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.JG!MTB"
        threat_id = "2147744396"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f4 64 89 0d 00 00 00 00 59 5f 5f 5e 5b 8b e5 5d 51 c3 8b 4d [0-2] 33 cd e8 [0-4] e9}  //weight: 1, accuracy: Low
        $x_1_2 = {50 6a 00 6a 01 6a 00 8b 4d [0-2] 51 ff 15 [0-4] 85 c0 75 04 32 c0 eb 02 b0 01 8b 4d [0-2] 33 cd e8 [0-4] 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_3 = "CryptEncrypt" ascii //weight: 1
        $x_1_4 = "UnhookWindowsHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_JG_2147744396_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.JG!MTB"
        threat_id = "2147744396"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 10 00 00 ?? ?? ff}  //weight: 1, accuracy: Low
        $x_10_2 = {56 57 8b 7c [0-2] 8b ?? 8d 70 ?? eb ?? 8d [0-2] 66 8b [0-4] 66 85 ?? 75 ?? 2b ?? d1 ?? 8b ?? 8b ?? 33 ?? f7 ?? 83 c1 01 8a [0-2] 03 01 01 01 32 30 33 [0-3] 3b ?? ?? ?? ?? ?? ?? 5d c3}  //weight: 10, accuracy: Low
        $x_10_3 = {83 c1 01 8a [0-2] 30 [0-3] 3b [0-6] 5d c3 40 00 8b ?? 8d 70 ?? eb ?? 8d [0-2] 66 8b [0-4] 66 85 ?? 75 ?? 2b ?? d1 ?? 8b ?? 8b ?? 33 ?? f7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_KG_2147744397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.KG!MTB"
        threat_id = "2147744397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 ?? 00 00 ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 04 68 00 ?? 00 00 ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c0 02 66 85 [0-3] 2b ?? d1 f8 48 c3}  //weight: 1, accuracy: Low
        $x_1_4 = {d1 f8 48 c3 19 00 66 8b [0-4] 66 85 [0-3] 2b}  //weight: 1, accuracy: Low
        $x_20_5 = {8b e5 5d c3 32 00 8b [0-4] 33 d2 f7 ?? 8b [0-2] 03 [0-2] 8b 4d ?? 8a ?? 03 01 01 01 32 30 33 [0-2] 8b 4d ?? 03 4d ?? 88}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_RS_2147744451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RS!MSR"
        threat_id = "2147744451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "A:\\Czxasd.nmjk" ascii //weight: 1
        $x_1_2 = "ddeexec" ascii //weight: 1
        $x_1_3 = "[printto(\"%1\",\"%2\",\"%3\",\"%4\")]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RS_2147744451_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RS!MSR"
        threat_id = "2147744451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "BubbleBreaker.EXE" wide //weight: 1
        $x_1_2 = "LockFile" ascii //weight: 1
        $x_1_3 = "virtualalloc" ascii //weight: 1
        $x_1_4 = "Sleep" ascii //weight: 1
        $x_1_5 = {66 0f b6 32 8b cf 66 d3 e6 42 66 f7 d6 0f b7 ce 88 28 88 48 ?? 03 45 ?? ff 4d ?? 75}  //weight: 1, accuracy: Low
        $x_1_6 = {2a c3 88 07 47 ff 4d [0-4] 8a 02 42 3a c3 7d [0-4] eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RS_2147744451_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RS!MSR"
        threat_id = "2147744451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 33 f2 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 8b d6 8b ca b8 89 dc 00 00 03 c1 2d 89 dc 00 00 89 45 fc a1 ?? ?? ?? ?? 8b 4d fc 89 08 5e 8b e5 5d}  //weight: 1, accuracy: Low
        $x_1_3 = "xrMofrrIj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Emotet_F_2147744472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.F!MTB"
        threat_id = "2147744472"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Emotic.exe" ascii //weight: 1
        $x_1_2 = "@.eh_fram" ascii //weight: 1
        $x_1_3 = "memcpy" wide //weight: 1
        $x_1_4 = "LoadResource" wide //weight: 1
        $x_1_5 = "VirtualAlloc" wide //weight: 1
        $x_1_6 = "CryptEncrypt" wide //weight: 1
        $x_1_7 = "CryptAcquireContextW" wide //weight: 1
        $x_1_8 = {c7 44 24 0c 40 00 00 00 c7 44 24 08 00 10 00 00 89 44 24 04 c7 04 24 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_SC_2147744478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SC!MSR"
        threat_id = "2147744478"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\ProgramData\\" wide //weight: 1
        $x_1_2 = "The document" wide //weight: 1
        $x_1_3 = "Please enter a currency" wide //weight: 1
        $x_1_4 = "cyBFsCvXwm.exe" ascii //weight: 1
        $x_1_5 = "PIFMGR.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Emotet_SD_2147744480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SD!MSR"
        threat_id = "2147744480"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\ProgramData\\" wide //weight: 1
        $x_1_2 = "Crypt" wide //weight: 1
        $x_1_3 = "ESET Stupid" ascii //weight: 1
        $x_1_4 = "money" ascii //weight: 1
        $x_1_5 = "libgcj-12.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_SE_2147744517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SE!MSR"
        threat_id = "2147744517"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-FUC%" ascii //weight: 1
        $x_1_2 = "LockWindowUpdate" ascii //weight: 1
        $x_1_3 = "ChildCount" wide //weight: 1
        $x_1_4 = "NoNetConnectDisconnect" ascii //weight: 1
        $x_1_5 = "LinkingDoc" ascii //weight: 1
        $x_1_6 = "NoRecentDocsHistory" ascii //weight: 1
        $x_1_7 = "Erase everything" wide //weight: 1
        $x_1_8 = "spiro.EXE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_SF_2147744518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SF!MSR"
        threat_id = "2147744518"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "viewexd.dll" ascii //weight: 1
        $x_1_2 = "LockFile" ascii //weight: 1
        $x_1_3 = "&Hide" wide //weight: 1
        $x_1_4 = "accDescription" wide //weight: 1
        $x_1_5 = "NoNetConnectDisconnect" ascii //weight: 1
        $x_1_6 = "RecentDocsHistory" ascii //weight: 1
        $x_1_7 = "create empty document" wide //weight: 1
        $x_1_8 = "enter a currency" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PI_2147744576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PI!MTB"
        threat_id = "2147744576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {6a 01 6a 10 8b 55 10 52 8b 45 ?? 50 ff 55 ?? 85 c0 75 04 33 c0 eb ?? 8d 4d ?? 51 6a 01 8b 55 ?? 52 68 01 68 00 00 8b 45 ?? 50 ff 55 ?? 85 c0 75 04 33 c0 eb ?? 6a 40 68 00 10 00 00 8b 4d 0c 51 6a 00 ff 55}  //weight: 20, accuracy: Low
        $x_1_2 = {55 8b ec 83 ec ?? 6a 00 68 ?? 01 00 00 e8 ?? ?? ?? ?? 83 c4 08 50 e8 ?? ?? ?? ?? 83 c4 04 50 e8 ?? ?? ?? ?? 83 c4 04 89 45 ?? 6a 00 68 ?? 01 00 00 e8 ?? ?? ?? ?? 83 c4 08 50 e8 ?? ?? ?? ?? 83 c4 04 50 e8 ?? ?? ?? ?? 83 c4 04 89 45}  //weight: 1, accuracy: Low
        $x_20_3 = {6a 01 6a 10 52 50 ff 54 24 ?? 85 c0 74 ?? 8b 54 24 14 8b 44 24 10 8d 4c 24 18 51 6a 01 52 68 01 68 00 00 50 ff 54 24 ?? 85 c0 74 ?? 8b 4c 24 58 6a 40 68 00 10 00 00 51 6a 00 ff d3}  //weight: 20, accuracy: Low
        $x_1_4 = {68 70 69 86 5d e8 ?? ?? ?? ?? 68 54 ca af 91 8b ?? e8 ?? ?? ?? ?? 68 da 8b c2 43 8b ?? e8 ?? ?? ?? ?? 68 88 25 24 d9 8b ?? e8 ?? ?? ?? ?? 68 30 a1 05 41}  //weight: 1, accuracy: Low
        $x_20_5 = {53 6a 10 ff 75 10 ff 75 f8 ff 55 ec 85 c0 74 ?? 8d 45 f4 50 53 ff 75 f8 68 01 68 00 00 ff 75 fc ff 55 ?? 85 c0 74 ?? 6a 40 68 00 10 00 00 ff 75 0c 56 ff 55 ?? ff 75 0c 8b f8 ff 75 08 57 ff 55}  //weight: 20, accuracy: Low
        $x_1_6 = {55 8b ec 83 ec ?? 53 56 33 f6 57 56 68 ?? 01 00 00 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 56 68 ?? 01 00 00 89 45 ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 56}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_LG_2147744579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.LG!MTB"
        threat_id = "2147744579"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 10 00 00 [0-4] 6a 00 ff [0-3] ff [0-3] 89 44 [0-2] ff [0-3] 50 ff 54 [0-2] 83 c4 ?? ff [0-3] 8d 44 [0-2] 50 ff [0-3] 6a 00 6a 01 6a 00 ff 74 [0-2] ff 54 [0-2] 85 c0 [0-6] 8b 44 [0-2] 5f 5e 5d 5b 83 c4 ?? c3 [0-80] 83 c4 ?? ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_SG_2147744598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SG!MSR"
        threat_id = "2147744598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Users\\User\\Desktop\\2008\\Tracker\\Release\\Tracker.pdb" ascii //weight: 1
        $x_1_2 = "LockFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GM_2147744603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GM!MTB"
        threat_id = "2147744603"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fBMcFdauo" wide //weight: 1
        $x_1_2 = "CryptEncrypt" wide //weight: 1
        $x_1_3 = "LayvXBcOppdgzCgnncA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Emotet_SH_2147744606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SH!MSR"
        threat_id = "2147744606"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CCircFileDemo.EXE" wide //weight: 1
        $x_1_2 = "ShareViolation" ascii //weight: 1
        $x_1_3 = "abrar_@yahoo.com" ascii //weight: 1
        $x_1_4 = "ExcludeUpdate" ascii //weight: 1
        $x_1_5 = "create empty document" wide //weight: 1
        $x_1_6 = "&Hide" wide //weight: 1
        $x_1_7 = "DestroyWindow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DHJ_2147744607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DHJ!MTB"
        threat_id = "2147744607"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 3e 46 3b f3 7c c2 31 00 69 c0 ?? ?? ?? ?? 68 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 05 ?? ?? ?? ?? 6a 00 a3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? a0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DHK_2147744608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DHK!MTB"
        threat_id = "2147744608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ca 8d 14 30 33 ca 2b f9 e8 ?? ?? ?? ?? 4d 75 ?? 8b 44 24 1c 89 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DHL_2147744609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DHL!MTB"
        threat_id = "2147744609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c8 2b f9 8b cf 8b c7 c1 e9 05 03 4d fc c1 e0 04 03 45 f8 33 c8 8d 04 3b 33 c8 8d 9b ?? ?? ?? ?? 8b 45 f4 2b f1 4a 75 ?? 8b 55 08 89 7a 04 5f 89 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DWTD_2147744610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DWTD!MTB"
        threat_id = "2147744610"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "VzcsSxdKopTdfCVS" ascii //weight: 10
        $x_10_2 = "DaxczsderFGvuj.exe" ascii //weight: 10
        $x_10_3 = "Emotic.exe" ascii //weight: 10
        $x_10_4 = "ZNqzXGGsvwLm" ascii //weight: 10
        $x_1_5 = "memcpy" wide //weight: 1
        $x_1_6 = "LockResource" wide //weight: 1
        $x_1_7 = "CryptAcquireContextW" wide //weight: 1
        $x_1_8 = "VirtualAlloc" wide //weight: 1
        $x_1_9 = "CryptEncrypt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_SJ_2147744657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SJ!MSR"
        threat_id = "2147744657"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LockWindowUpdate" ascii //weight: 1
        $x_1_2 = "DocsHistory" wide //weight: 1
        $x_1_3 = "NoNetConnectDisconnect" ascii //weight: 1
        $x_1_4 = "RestrictRun" ascii //weight: 1
        $x_1_5 = "NoRecentDocsHistory" ascii //weight: 1
        $x_1_6 = "Erase everything" wide //weight: 1
        $x_1_7 = "Open this document" wide //weight: 1
        $x_1_8 = "DIBLOOK" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RQ_2147744659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RQ!MSR"
        threat_id = "2147744659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d8 5c 0b 8b 42 30 f8 b3 75 3c 0c 3a 0a ff 33 b0 a2 75 e8 96 bb c0 cc 3f 71 95 96 66 7a 45 8c 99 80 e8 d6 fa 37 e3 d4 e6 87 dd f8 87 b6 4b 09 2f}  //weight: 1, accuracy: High
        $x_1_2 = {8b ec 83 c4 c0 53 68 12 47 85 38 e8 63 d4 ff ff 59 89 45 e0 68 47 98 b8 d4 e8 55 d4 ff ff 59 89 45 c0 68 b5 40 d7 a3 e8 47 d4 ff ff 59 89 45 c4 68 07 77 54 3b e8 39 d4 ff ff 59 89 45 e4 68 3f 92 31 19 e8 2b d4 ff ff 59 89 45 e8 68 c8 0d c5 f8 e8 1d d4 ff ff 59 89 45 ec 68 27 c2 44 e0 e8 0f d4 ff ff 59}  //weight: 1, accuracy: High
        $x_1_3 = {6a 40 68 00 10 00 00 8b 55 0c 52 6a 00 ff 55 c0 8b d8 8b 45 0c 50 8b 55 08 52 53 ff 55 e0 83 c4 0c 8b 4d 0c 51 8d 45 0c 50 53 6a 00 6a 01 6a 00 8b 55 f4 52 ff 55 e4 85 c0 75 04 33 c0 eb 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RQ_2147744659_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RQ!MSR"
        threat_id = "2147744659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 83 0c 02 00 00 33 d2 40 25 ff 00 00 00 89 83 0c 02 00 00 8a 14 03 8b 8b 10 02 00 00 03 d1 81 e2 ff 00 00 00 89 93 10 02 00 00 33 d2 8b 83 0c 02 00 00 8a 14 03 89 93 18 02 00 00 8b 8b 10 02 00 00 8b 93 0c 02 00 00 8a 04 0b 30 04 13 8b 8b 0c 02 00 00 8b 93 10 02 00 00 8a 04 0b 30 04 13 8b 8b 10 02 00 00 8b 93 0c 02 00 00 8a 04 0b 30 04 13 8b 8b 10 02 00 00 8a 83 18 02 00 00 88 04 0b ff 83 04 02 00 00 8b 93 04 02 00 00 81 fa 00 0c 00 00 0f 8c}  //weight: 1, accuracy: High
        $x_1_2 = {8b 8b 08 02 00 00 8a 14 03 0f b6 84 03 00 01 00 00 03 d1 03 d0 81 e2 ff 00 00 00 89 93 08 02 00 00 8b 83 04 02 00 00 8a 14 13 30 14 03 8b 93 04 02 00 00 8b 83 08 02 00 00 8a 0c 13 30 0c 03 8b 93 08 02 00 00 8b 83 04 02 00 00 8a 0c 13 30 0c 03 ff 83 04 02 00 00 8b 83 04 02 00 00 3d 00 01 00 00 7c 9a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_SU_2147744700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SU!MSR"
        threat_id = "2147744700"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.PlanetCpp.com" ascii //weight: 1
        $x_1_2 = "PlanetCpp richedit example." ascii //weight: 1
        $x_1_3 = "Another program is using the clipboard, please wait until that program finishes." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PD_2147744705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PD!MSR"
        threat_id = "2147744705"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%ATTACKERIP%" wide //weight: 2
        $x_2_2 = "get_AttackerIp" ascii //weight: 2
        $x_2_3 = "<AttackerIp>k__BackingField" ascii //weight: 2
        $x_1_4 = "get_CurrentThreatScenario" ascii //weight: 1
        $x_1_5 = "_lazyFileLogger" ascii //weight: 1
        $x_1_6 = "_lazyRemoteManagementClient" ascii //weight: 1
        $x_1_7 = "get_password" ascii //weight: 1
        $x_1_8 = "get_ProcessMemory" ascii //weight: 1
        $x_1_9 = "get_needs_remote_creds" ascii //weight: 1
        $x_1_10 = "get_remote_machine_logins" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_RV_2147744721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RV!MSR"
        threat_id = "2147744721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff d2 83 ec 10 89 45 f4 8b 45 d4 8b 55 0c 89 54 24 08 8b 55 08 89 54 24 04 8b 55 f4 89 14 24 ff d0 8b 4d d8 8b 55 0c 8b 45 e8 89 54 24 18 8d 55 0c 89 54 24 14 8b 55 f4 89 54 24 10 c7 44 24 0c 00 00 00 00 c7 44 24 08 01 00 00 00 c7 44 24 04 00 00 00 00 89 04 24 ff d1 83 ec 1c 85 c0 0f 94 c0 84 c0 74 07 b8 00 00 00 00 eb 03}  //weight: 1, accuracy: High
        $x_1_2 = {55 89 e5 53 83 ec 74 c7 04 24 c0 07 b6 69 e8 6e fe ff ff 89 45 d4 c7 04 24 dd 03 de 49 e8 5f fe ff ff 89 45 b4 c7 04 24 cf f3 4b 2c e8 50 fe ff ff 89 45 b8 c7 04 24 55 7a 8d 10 e8 41 fe ff ff 89 45 d8 c7 04 24 32 2f 83 c1 e8 32 fe ff ff 89 45 dc c7 04 24 a3 ed 12 b8 e8 23 fe ff ff 89 45 e0 c7 04 24 78 5d 52 4d e8 14 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_MG_2147744738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.MG!MTB"
        threat_id = "2147744738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 10 00 00 [0-3] 51 6a 00 ff 55 ?? 89 [0-2] 8b [0-3] 8b [0-2] 50 8b [0-3] ff [0-2] 83 ?? 0c 8b [0-3] 8d [0-2] 50 8b [0-3] 6a 00 6a 01 6a 00 8b 55 ?? 52 ff 55 ?? 85 c0 [0-2] 33 c0 eb [0-200] 83 c4 0c 89 [0-2] 8b [0-2] 89 [0-2] ff 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_I_2147744746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.I!MTB"
        threat_id = "2147744746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ff 5f 5d c3 4f 00 b8 ?? ?? ?? ?? 31 0d ?? ?? ?? ?? 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 8b ff 5f 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 fc 8d 84 02 ?? ?? ?? ?? 8b 4d 08 03 01 8b 55 08 89 02 8b 45 08 8b 08 81 e9 ?? ?? ?? ?? 8b 55 08 89 0a 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_I_2147744746_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.I!MTB"
        threat_id = "2147744746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 53 ff 75 f8 68 01 68 00 00 ff 75 fc ff 55 f0 85 c0 74 ?? 6a 40 68 00 10 00 00 ff 75 0c 56 ff 55 c0 ff 75 0c 8b f8 ff 75 08 57 ff 55 e0 83 c4 0c 8d 45 0c ff 75 0c 50 57 56 53 56 ff 75 f4 ff 55 e4 f7 d8 1b c0 23 c7 5f 5e 5b c9 c3}  //weight: 1, accuracy: Low
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
        $x_1_3 = "SetUnhandledExceptionFilter" ascii //weight: 1
        $x_1_4 = {89 55 08 8b 54 91 08 89 54 99 08 8b 5d 08 89 55 fc 8b 55 10 89 54 99 08 8b 5d fc 03 da 23 d8 8a 54 99 08 32 57 06 ff 4d f8 88 56 06 74 ?? 8b 55 14 e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CA_2147744751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CA!MTB"
        threat_id = "2147744751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 e3 c8 20 6e 3b 31 d8 89 d3 c1 e3 19 c1 fb 1f 81 e3 90 41 dc 76 31 d8 c1 e2 18 c1 fa 1f 81 e2 20 83 b8 ed 31 d0 0f b6 11 41 85 d2 0f}  //weight: 1, accuracy: High
        $x_1_2 = {8b 06 01 d8 8b 55 e4 30 10 43 8b 06 3b 58 f4 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CA_2147744751_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CA!MTB"
        threat_id = "2147744751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e1 1c c1 f9 1f 81 e1 32 88 db 0e 33 c1}  //weight: 1, accuracy: High
        $x_1_2 = {c1 e1 1a c1 f9 1f 81 e1 c8 20 6e 3b 33 c1}  //weight: 1, accuracy: High
        $x_1_3 = {8b 01 ba ff fe fe 7e 03 d0 83 f0 ff 33 c2 83 c1 04 a9 00 01 01 81 74 e8 8b 41 fc 84 c0 74 32}  //weight: 1, accuracy: High
        $x_1_4 = {ff e0 5f 5e 5b c9 c2 08 00 58 59 87 04 24 ff e0 58 59 87 04 24 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CA_2147744751_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CA!MTB"
        threat_id = "2147744751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f8 33 d2 8b c3 f7 f1 8b ce 52 e8 ?? ?? ?? ?? 8a 00 30 07 43 3b 5d 20 72}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 f7 f1 52 8b 4d 1c e8 ?? ?? ?? ?? 8b 55 e8 8a 0a 32 08 8b 55 e8 88 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_CA_2147744751_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CA!MTB"
        threat_id = "2147744751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "0CnO(WMU(Kc5SQxl8Bu#R*jVY0AAKSg9s9OU4N^+xC6Zs+" ascii //weight: 3
        $x_3_2 = "RestrictRun" ascii //weight: 3
        $x_3_3 = "NoNetConnectDisconnect" ascii //weight: 3
        $x_3_4 = "NoRecentDocsHistory" ascii //weight: 3
        $x_3_5 = "DllRegisterServer" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_SK_2147744761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SK!MSR"
        threat_id = "2147744761"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 10 88 18 8b 5d f8 88 14 33 0f b6 00 0f b6 d2 03 c2 33 d2 f7 f1 8b 4d f0 8a 04 32 32 04 39 88 07 47 ff 4d 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_SK_2147744761_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SK!MSR"
        threat_id = "2147744761"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cvdffxcdfsdxxzSaw" ascii //weight: 1
        $x_1_2 = "SetFileSecurity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_SL_2147744763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SL!MSR"
        threat_id = "2147744763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Binary2C++211132512008\\Release\\Binary2C++.pdb" ascii //weight: 1
        $x_1_2 = "Target file is written" ascii //weight: 1
        $x_1_3 = "cvfGbzxDSwKlmpSxcZwA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_NG_2147744847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.NG!MTB"
        threat_id = "2147744847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 10 00 00 [0-35] 83 c4 0c [0-35] f7 d8 1b c0 [0-150] 83 c4 0c ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {81 e2 ff 00 00 00 c1 [0-2] 8b [0-3] 0b [0-2] c1 [0-2] 33 ?? 3b 74 [0-2] 89 [0-2] 8d 76 [0-4] 0f [0-75] 81 ?? ff 00 00 00 [0-3] 32 ?? 8d [0-2] 8b [0-2] 3b [0-2] [0-15] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_OG_2147744849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.OG!MTB"
        threat_id = "2147744849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e2 ff 00 00 00 89 [0-5] 8b [0-5] 8a [0-2] 30 [0-2] 8b [0-5] 8b [0-5] 8a [0-2] 30 [0-2] 8b [0-5] 8b [0-5] 8a [0-2] 30 [0-2] ff [0-5] 8b [0-5] 3d [0-100] 81 ?? ff 00 00 00 [0-75] 30 [0-75] 30}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 68 00 10 00 00 [0-35] 83 c4 0c [0-35] 6a 00 6a 01 6a 00 [0-150] 83 c4 0c [0-15] ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_SM_2147744865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SM!MSR"
        threat_id = "2147744865"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zsDFccKLMNvcfDxr" ascii //weight: 1
        $x_1_2 = "money" ascii //weight: 1
        $x_1_3 = "please enter your name" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AH_2147744872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AH!MSR"
        threat_id = "2147744872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Project1.exe" ascii //weight: 1
        $x_1_2 = "libgcj-12.dll" ascii //weight: 1
        $x_1_3 = "Broken promise" ascii //weight: 1
        $x_1_4 = "Promise already satisfied" ascii //weight: 1
        $x_1_5 = "Future already retrieved" ascii //weight: 1
        $x_1_6 = "Infinity" ascii //weight: 1
        $x_1_7 = "special.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_SN_2147744905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SN!MSR"
        threat_id = "2147744905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "fsgjhghjfdFADZxcRFT" ascii //weight: 2
        $x_2_2 = "czssdkgnbnGDFfrtyaXl" ascii //weight: 2
        $x_1_3 = {50 72 6f 6a 65 63 74 [0-2] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = "SetFileSecurity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_PJ_2147744927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PJ!MTB"
        threat_id = "2147744927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {c7 04 24 38 d5 39 53 e8 ?? ?? ?? ?? 89 [0-2] c7 04 24 f6 61 79 e6 e8 ?? ?? ?? ?? 89 [0-2] c7 04 24 2d 00 b4 ad e8 ?? ?? ?? ?? 89 [0-2] c7 04 24 7e 18 2a bf e8 ?? ?? ?? ?? 89 [0-2] c7 04 24 10 59 4b 4d e8 ?? ?? ?? ?? 89 [0-2] c7 04 24 e0 95 66 b3 e8 ?? ?? ?? ?? 89 [0-2] c7 04 24 7b 8c 58 56 e8}  //weight: 20, accuracy: Low
        $x_20_2 = {c7 04 24 17 cf 43 f9 e8 ?? ?? ?? ?? 89 [0-5] c7 04 24 31 82 6d 75 e8 ?? ?? ?? ?? 89 [0-5] c7 04 24 16 72 b3 9b e8 ?? ?? ?? ?? 89 [0-5] c7 04 24 b9 fb 3e 2c e8 ?? ?? ?? ?? 89 [0-5] c7 04 24 3d 1f 33 0a e8 ?? ?? ?? ?? 89 [0-5] c7 04 24 e6 9c f6 80 e8 ?? ?? ?? ?? 89 [0-5] c7 04 24 f8 de d1 9c e8}  //weight: 20, accuracy: Low
        $x_1_3 = {c7 44 24 0c 01 00 00 00 c7 44 24 08 10 00 00 00 8b 45 10 89 44 24 04 8b 45 ?? 89 04 24 ff d7 83 ec 10 85 c0 0f 84 ?? ?? ?? ?? 8d 45 ?? 89 44 24 10 c7 44 24 0c 01 00 00 00 8b 45 ?? 89 44 24 08 c7 44 24 04 01 68 00 00 8b 45 ?? 89 04 24 ff 55}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 44 24 0c 01 00 00 00 c7 44 24 08 10 00 00 00 89 5c 24 04 8b 44 24 ?? 89 04 24 ff 54 24 ?? 83 ec 10 85 c0 0f 84 ?? ?? ?? ?? 8d 44 24 ?? 89 44 24 10 c7 44 24 0c 01 00 00 00 8b 44 24 ?? 89 44 24 08 c7 44 24 04 01 68 00 00 8b 44 24 ?? 89 04 24 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_J_2147744928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.J!MTB"
        threat_id = "2147744928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "@.eh_fram" ascii //weight: 1
        $x_1_2 = "SetUnhandledExceptionFilter" ascii //weight: 1
        $x_1_3 = {c7 44 24 0c 40 00 00 00 c7 44 24 08 00 10 00 00 89 44 24 04 c7 04 24 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {c7 44 24 0c 40 00 00 00 c7 44 24 08 00 10 00 00 c7 04 24 00 00 00 00 89 44 24 04}  //weight: 1, accuracy: High
        $x_1_5 = {c7 44 24 0c 00 00 00 00 c7 44 24 08 01 00 00 00 c7 44 24 04 00 00 00 00 89 44 24 18}  //weight: 1, accuracy: High
        $x_1_6 = {c7 44 24 0c 00 00 00 00 c7 44 24 08 01 00 00 00 c7 44 24 04 00 00 00 00 89 04 24}  //weight: 1, accuracy: High
        $x_1_7 = {9c 9c 58 89 c2 35 00 00 20 00 50 9d 9c 58 9d 31 d0 a9 00 00 20 00 0f 84 ?? 00 00 00 53 31 c0 0f a2 85 c0 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Emotet_J_2147744928_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.J!MTB"
        threat_id = "2147744928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 10 00 00 8d 4d 0c 51 6a 00 8d 55 c0 52 ff 55 d0 50 ff 55 cc}  //weight: 1, accuracy: High
        $x_1_2 = {6a 40 68 00 10 00 00 8d 55 0c 52 6a 00 8d 45 bc 50 ff 55 cc 50 ff 55 c8}  //weight: 1, accuracy: High
        $x_1_3 = {6a 40 68 00 10 00 00 50 8d 45 f8 53 50 ff 55 c0 50 ff 55 bc}  //weight: 1, accuracy: High
        $x_1_4 = {6a 40 68 00 10 00 00 8d 54 24 64 52 6a 00 8d 44 24 24 50 ff d5 50 ff 54 24 38}  //weight: 1, accuracy: High
        $x_1_5 = {6a 40 8d 45 0c 68 00 10 00 00 50 33 f6 8d 45 f8 56 50 ff 55 c0 50 ff 55 bc}  //weight: 1, accuracy: High
        $x_1_6 = {ff 55 d0 50 ff 55 cc 1f 00 8b 0d ?? ?? ?? 00 51 8b 15 ?? ?? ?? 00 52 8d 45 0c 50 6a 00 8d 4d c0 51 ff 55 d0 50 ff 55 cc}  //weight: 1, accuracy: Low
        $x_1_7 = {ff 75 0c ff 75 08 ff 75 f8 ff 55 d8 2f 00 83 c4 40 ff 35 ?? ?? ?? 00 8d 45 f0 ff 35 ?? ?? ?? 00 50 53 8d 45 f8 50 ff 55 bc 50 ff 55 b8 ff 75 0c ff 75 08 ff 75 f8 ff 55 d8}  //weight: 1, accuracy: Low
        $x_1_8 = {ff 55 b8 ff 75 0c ff 75 08 ff 75 f8 ff 55 d8 2f 00 ff 35 ?? ?? ?? 00 8d 45 f0 ff 35 ?? ?? ?? 00 50 8d 45 f8 56 50 ff 55 bc 50 ff 55 b8 ff 75 0c ff 75 08 ff 75 f8 ff 55 d8}  //weight: 1, accuracy: Low
        $x_1_9 = {8b 45 0c 50 8d 4d 0c 51 8b 55 c0 52 6a 00 6a 01 6a 00 8b 45 c4 50 ff 55 f0 85 c0 75 04 33 c0 eb 03 8b 45 c0 8b e5 5d c3}  //weight: 1, accuracy: High
        $x_1_10 = {8b 55 0c 52 8d 45 0c 50 8b 4d bc 51 6a 00 6a 01 6a 00 8b 55 fc 52 ff 55 ec 85 c0 75 04 33 c0 eb 03 8b 45 bc 8b e5 5d c3}  //weight: 1, accuracy: High
        $x_1_11 = {8d 45 0c ff 75 0c 50 ff 75 f8 53 6a 01 53 ff 75 f0 ff 55 e0 f7 d8 1b c0 23 45 f8 5f 5e 5b c9 c3}  //weight: 1, accuracy: High
        $x_1_12 = {8b 44 24 5c 8b 54 24 14 50 8b 44 24 20 8d 4c 24 60 51 52 6a 00 6a 01 6a 00 50 ff 54 24 60 5f f7 d8 5e 1b c0 23 44 24 0c 5d 5b 83 c4 44 c3}  //weight: 1, accuracy: High
        $x_1_13 = {83 c4 0c 8d 45 0c ff 75 0c 50 ff 75 f8 56 6a 01 56 ff 75 f0 ff 55 e0 f7 d8 1b c0 23 45 f8 5f 5e 5b c9 c3}  //weight: 1, accuracy: High
        $x_1_14 = {8b 55 0c 52 8d 45 0c 50 8b 4d c0 51 6a 00 6a 01 6a 00 8b 55 c4 52 ff 55 f0 85 c0 75 04 33 c0 eb 03 8b 45 c0 8b e5 5d c3}  //weight: 1, accuracy: High
        $x_1_15 = {83 c4 0c ff 75 0c 8d 45 0c 50 ff 75 f8 53 6a 01 53 ff 75 ec ff 55 dc f7 d8 1b c0 23 45 f8 5f 5e 5b c9 c3}  //weight: 1, accuracy: High
        $x_1_16 = {ff 55 d8 83 c4 0c 8d 45 0c ff 75 0c 50 ff 75 f8 56 53 56 ff 75 ec ff 55 dc f7 d8 1b c0 23 45 f8 5f 5e 5b c9 c3}  //weight: 1, accuracy: High
        $x_1_17 = "SetUnhandledExceptionFilter" ascii //weight: 1
        $x_1_18 = "_except_handler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Emotet_AG_2147744930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AG!MSR"
        threat_id = "2147744930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Project3.exe" ascii //weight: 1
        $x_1_2 = "zcDDFvhjnmUfdSAwKMNb" ascii //weight: 1
        $x_1_3 = "Actx" ascii //weight: 1
        $x_1_4 = "Choose a Folder or Create a New One" ascii //weight: 1
        $x_1_5 = "No Selection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AG_2147744930_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AG!MSR"
        threat_id = "2147744930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AfxOldWndProc423" ascii //weight: 1
        $x_1_2 = "AfxOleControl70s" ascii //weight: 1
        $x_1_3 = "Sketch Document" ascii //weight: 1
        $x_1_4 = "AfxMDIFrame70s" ascii //weight: 1
        $x_1_5 = "Local AppWizard-Generated Applications" ascii //weight: 1
        $x_1_6 = "Sketch MFC Appli" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PK_2147745019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PK!MTB"
        threat_id = "2147745019"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 53 83 ec ?? c7 04 24 ?? ?? ?? ?? e8 ?? ?? ff ff 89 45 ?? c7 04 24 ?? ?? ?? ?? e8 ?? ?? ff ff 89 45 ?? c7 04 24 ?? ?? ?? ?? e8 ?? ?? ff ff 89 45 ?? c7 04 24 ?? ?? ?? ?? e8 ?? ?? ff ff 89 45 ?? c7 04 24 ?? ?? ?? ?? e8 ?? ?? ff ff 89 45 ?? c7 04 24 ?? ?? ?? ?? e8 ?? ?? ff ff 89 45 ?? c7 04 24 ?? ?? ?? ?? e8 ?? ?? ff ff 89 45}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 10 08 00 00 00 c7 44 24 0c 01 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 00 00 00 00 8d 45 ?? 89 04 24 ff d2 83 ec 14 85 c0 0f 94 c0 84 c0 74 ?? 8b 55 ?? c7 44 24 10 00 00 00 f0 c7 44 24 0c 01 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 00 00 00 00 8d 45 f0 89 04 24 ff d2 83 ec 14 85 c0 0f 94 c0 84 c0 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_SO_2147745021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SO!MSR"
        threat_id = "2147745021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DDRAW.dll" ascii //weight: 1
        $x_1_2 = "DestroyWindow" ascii //weight: 1
        $x_1_3 = "SetFileSecurity" ascii //weight: 1
        $x_1_4 = "Broken promise" ascii //weight: 1
        $x_1_5 = "Resume Game" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_H_2147745049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.H!MTB"
        threat_id = "2147745049"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 0c 40 00 00 00 c7 44 24 08 00 10 00 00 89 44 24 04 c7 04 24 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {c7 44 24 0c 40 00 00 00 c7 44 24 08 00 10 00 00 c7 04 24 00 00 00 00 89 44 24 04}  //weight: 1, accuracy: High
        $x_1_3 = {c7 44 24 0c 40 00 00 00 c7 44 24 08 00 10 00 00 8b 44 24 64 89 44 24 04 c7 04 24 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {c7 44 24 0c 40 00 00 00 c7 44 24 08 00 10 00 00 8b 84 24 ?? ?? 00 00 89 44 24 04 c7 04 24 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {c7 44 24 0c 00 00 00 00 c7 44 24 08 01 00 00 00 c7 44 24 04 00 00 00 00 89 44 24 18}  //weight: 1, accuracy: High
        $x_1_6 = {c7 44 24 0c 00 00 00 00 c7 44 24 08 01 00 00 00 c7 44 24 04 00 00 00 00 89 04 24}  //weight: 1, accuracy: High
        $x_1_7 = {c7 44 24 0c 00 00 00 00 c7 44 24 08 01 00 00 00 c7 44 24 04 00 00 00 00 8b 44 24 3c 89 04 24}  //weight: 1, accuracy: High
        $x_1_8 = {c7 44 24 0c 00 00 00 00 c7 44 24 08 01 00 00 00 c7 44 24 04 00 00 00 00 8b 84 24 ?? ?? 00 00 89 04 24}  //weight: 1, accuracy: Low
        $x_1_9 = "SetUnhandledExceptionFilter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Emotet_AM_2147745057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AM!MSR"
        threat_id = "2147745057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "r1gF5Mg5svFVNfZ" ascii //weight: 1
        $x_1_2 = "ZASSNHYT.EXE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DHQ_2147745113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DHQ!MTB"
        threat_id = "2147745113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 01 ba ff fe fe 7e 03 d0 83 f0 ff 33 c2 83 c1 04}  //weight: 1, accuracy: High
        $x_1_2 = {33 d2 8a 51 01 8b 4d f8 8b 04 81 33 c2 8b 4d 14 88 41 01 8b 55 f4 83 c2 01 81 e2 ff 00 00 00 89 55 f4}  //weight: 1, accuracy: High
        $x_5_3 = "ExlO68OtffaCX0z9rX" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RM_2147745142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RM!MTB"
        threat_id = "2147745142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HcfyvgOhbvg" ascii //weight: 1
        $x_1_2 = "YyvgKbuvgy" ascii //weight: 1
        $x_1_3 = "WxdtcfvgOnjkhbjg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RM_2147745142_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RM!MTB"
        threat_id = "2147745142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "s&pW1VBVMba8E@r%UV_mj1G$2YOLSQ+LjC" ascii //weight: 1
        $x_1_2 = {81 c9 00 10 00 00 51 8b 45 ?? 50 6a 00 6a ff ff 15 ?? ?? ?? ?? 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RM_2147745142_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RM!MTB"
        threat_id = "2147745142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "X>JTQ(DkT%xkH^8JpR@@8wXjyhZoyDEF7g#1kLDpm23pAI2ulwwyeV" ascii //weight: 1
        $x_1_2 = {68 00 30 00 00 8b 45 ?? 50 6a 00 6a ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RM_2147745142_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RM!MTB"
        threat_id = "2147745142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ancoxkm" ascii //weight: 1
        $x_1_2 = "aukjbzdloqqrfv" ascii //weight: 1
        $x_1_3 = "auxigugmftnxo" ascii //weight: 1
        $x_1_4 = "ckywegmtkvtcsn" ascii //weight: 1
        $x_1_5 = "eqqudqkdvqjbxvpwm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RM_2147745142_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RM!MTB"
        threat_id = "2147745142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b f9 57 56 6a 00 6a ff ff 15 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = "m_d#57%5ZNSE1nIgi1h&A9?9J%wfoPFnryY@JWU@X+_px*dLp%VxC_odQ?29j%vFv9iQ_S" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RM_2147745142_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RM!MTB"
        threat_id = "2147745142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "<MQEuIOwGl2Dz#WHQER4QN^6$UF#D7Y($(BWouH6q<d$wl6)QLgmb9XSKwu<pm#r5O?AE" ascii //weight: 1
        $x_1_2 = {81 c9 00 10 00 00 51 56 53 6a ff ff 15 ?? ?? ?? ?? eb ?? 6a 40 68 00 30 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GO_2147745188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GO!MTB"
        threat_id = "2147745188"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 f8 25 ff 00 00 00 66 31 ?? 66 89 [0-3] 8b [0-3] 8a [0-2] 8b [0-3] 32 [0-2] 8b 44 24 ?? 88 [0-2] 83 ?? 01 8b 44 24 ?? 39 ?? 8b [0-3] 89 [0-3] 89 [0-3] 89 fc 00 8b 44 [0-18] 81 [0-5] 01 f0 [0-8] 89 c6 c1 fe ?? c1 ee}  //weight: 1, accuracy: Low
        $x_1_2 = {25 ff 00 00 00 66 31 ?? 66 89 [0-3] 8b [0-3] 8a [0-2] 8b [0-3] 32 [0-2] 8b 44 24 ?? 88 [0-2] 83 ?? 01 8b 44 24 ?? 39 ?? 8b [0-3] 89 [0-3] 89 [0-3] 89 fc 00 8b 44 [0-18] 81 [0-5] 01 f0 [0-8] 89 c6 c1 fe ?? c1 ee}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_CC_2147745210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CC!MTB"
        threat_id = "2147745210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "#L6bOYO>IU2>cS42GIYuFyJD&G2Ic$JC+D^mM6Jm9bvc1DcK6" ascii //weight: 3
        $x_3_2 = "CreateStdAccessibleObject" ascii //weight: 3
        $x_3_3 = "NoRecentDocsHistory" ascii //weight: 3
        $x_3_4 = "FindResourceA" ascii //weight: 3
        $x_3_5 = "LoadResource" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CD_2147745211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CD!MTB"
        threat_id = "2147745211"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 14 8a 5c 24 17 8a d4 8a c8 c0 ea 04 c0 e1 02 0a d1 8a 4c 24 16 88 16 8a d1 8a c4 46 c0 ea 02 c0 e0 04 0a d0 8b 44 24 10 88 16 46 c0 e1 06 0a cb 33 d2 88 0e 46 85 c0}  //weight: 1, accuracy: High
        $x_1_2 = {6a 40 68 00 10 00 00 50 6a 00 ff 54 24 2c 8b 4c 24 58 8b 54 24 54 8b f0 51 52 56 ff 54 24 48 8b 44 24 64 8b 54 24 24 83 c4 0c 8d 4c 24 58 50 51 56 6a 00 6a 01 6a 00 52 ff 54 24 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CD_2147745211_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CD!MTB"
        threat_id = "2147745211"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {83 ec 1c 8b 45 08 89 45 f8 8b 45 0c 89 45 fc 8b 45 fc 8b 00 89 45 f4 8b 45 f8 8b 00 89 45 f0 8b 45 f0 8a 00 88 45 ef}  //weight: 10, accuracy: High
        $x_5_2 = "w!SleU++QhBmrFJ9SJ_RC^fO)2UxN5MlNF9S)g00ffH27*ixEFK*X&%K^@elV8LtI%PCk2o*1R+c6*tx2H" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CD_2147745211_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CD!MTB"
        threat_id = "2147745211"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "*WIMQV*4V7si#aHx?$s($mUz!k*eX()I5Z4#$o<i(oZdHAfE4mzS<1%@N@NGY5W^2bYYVVp)" ascii //weight: 3
        $x_3_2 = "RestrictRun" ascii //weight: 3
        $x_3_3 = "NoDrives" ascii //weight: 3
        $x_3_4 = "Other.dll" ascii //weight: 3
        $x_3_5 = "DllRegisterServer" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AP_2147745212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AP!MSR"
        threat_id = "2147745212"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BitmapCase.exe" wide //weight: 1
        $x_1_2 = "theblackhand BitmapCase" wide //weight: 1
        $x_1_3 = "App to hide files in BMP files" wide //weight: 1
        $x_1_4 = "i/Hp2Tm1/PQxM1" ascii //weight: 1
        $x_1_5 = "inistrator" ascii //weight: 1
        $x_1_6 = "iwb1Rbsjo3KsZ4A1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AW_2147745239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AW!MSR"
        threat_id = "2147745239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "libgcj-12.dll" ascii //weight: 1
        $x_1_2 = "SetFileSecurityW" ascii //weight: 1
        $x_1_3 = "Broken promise" ascii //weight: 1
        $x_1_4 = "Promise already satisfied" ascii //weight: 1
        $x_1_5 = "mx3yj{sGmOjZ}XX" ascii //weight: 1
        $x_1_6 = "play.shp" ascii //weight: 1
        $x_1_7 = "ZjxSSeoBOqLj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AZ_2147745332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AZ!MSR"
        threat_id = "2147745332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "msp_french.dll" ascii //weight: 1
        $x_1_2 = "msp_dutch.dll" ascii //weight: 1
        $x_1_3 = "msp_italian.dll" ascii //weight: 1
        $x_1_4 = "msp_german.dll" ascii //weight: 1
        $x_1_5 = "msp_portuguese.dll" ascii //weight: 1
        $x_1_6 = "msp_spanish.dll" ascii //weight: 1
        $x_1_7 = "ADZXADDSSQA.EXE" ascii //weight: 1
        $x_1_8 = "YyjSMIHmBbAapdZUWw" ascii //weight: 1
        $x_1_9 = "alwaysontop" ascii //weight: 1
        $x_1_10 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RB_2147745345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RB!MSR"
        threat_id = "2147745345"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Cascade_Cl1225958262002\\Release\\Cascade.pdb" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DHM_2147745350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DHM!MTB"
        threat_id = "2147745350"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 5c 24 1c c1 e3 02 0f b6 54 24 1d 89 d1 c1 f9 04 09 d9 88 0f 89 d3 c1 e3 04 0f b6 54 24 1e 89 d1 c1 f9 02 09 d9 88 4f 01 8d 4f 03 c1 e2 06 0a 54 24 1f 88 57 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DHP_2147745352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DHP!MTB"
        threat_id = "2147745352"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 ff 45 f8 8a 55 ?? 8a 4d ?? c1 f9 ?? c1 e2 ?? 0a d1 8b 4d f8 88 11 ff 45 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DHR_2147745353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DHR!MTB"
        threat_id = "2147745353"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 45 f9 8a 4d f8 8a 55 f9 c0 e8 04 c0 e1 02 0a c1 8a 4d fa 88 06 8a c1 c0 e8 02 c0 e2 04 0a c2 46 c0 e1 06 0a 4d fb 88 06 46 88 0e}  //weight: 1, accuracy: High
        $x_1_2 = {6a 40 68 00 10 00 00 ff 75 0c 56 ff 55 c0 ff 75 0c 8b f8 ff 75 08 57 ff 55 e0 83 c4 0c ff 75 0c 8d 45 0c 50 57 56 53 56 ff 75 f4 ff 55 e4 f7 d8 1b c0 23 c7}  //weight: 1, accuracy: High
        $x_1_3 = {57 57 57 57 ff d6 57 57 57 57 ff d6 57 57 57 57 ff d6 57 57 57 57 ff d6 57 57 57 57 ff d6 57 57 57 57}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DHS_2147745354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DHS!MTB"
        threat_id = "2147745354"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e2 02 0f b6 85 ?? ?? ?? ?? c1 f8 04 0b d0 8b 8d ?? ?? ?? ?? 88 11 8b 95 01 83 c2 01 89 95 01 0f b6 85 00 c1 e0 04}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 68 00 10 00 00 8d 55 0c 52 6a 00 8d 45 bc 50 ff 55 cc 50 ff 55 c8 8b 4d 0c 51 8b 55 08 52 8b 45 bc 50 ff 55 e8 83 c4 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PDS_2147745360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PDS!MTB"
        threat_id = "2147745360"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 83 c5 01 0f b6 94 14 ?? ?? ?? ?? 30 55}  //weight: 1, accuracy: Low
        $x_1_2 = "jIpOsJ6ku2XAqYpOGw67ZxD5hlf0kAWocp6m" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PDS_2147745360_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PDS!MTB"
        threat_id = "2147745360"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 5c 04 0c 30 5c 3c 10 30 5c 3c 14 8b c6 83 e0 03 83 c6 06 8a 54 04 0c 30 54 3c 11 30 54 3c 15}  //weight: 2, accuracy: High
        $x_2_2 = {2b c8 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 a4 2b d1 01 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 ec 8b 0d ?? ?? ?? ?? 89 88 06 00 8b 0d}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 45 f0 03 45 e8 8d 0c 17 33 c1 81 c7 47 86 c8 61 33 45 e0 2b d8 8b 45 d8 83 ee 01 75}  //weight: 2, accuracy: High
        $x_2_4 = {0f b6 5d 01 8b cf c1 e1 1c c1 f9 1f 81 e2 64 10 b7 1d 33 c2 81 e1 32 88 db 0e 33 c1 8b cf 8b d7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_GQ_2147745364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GQ!MTB"
        threat_id = "2147745364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ESET Stupid" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AW_2147745372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AW!MTB"
        threat_id = "2147745372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TFVGYBUH.DLL" ascii //weight: 1
        $x_1_2 = "EdrcfvtUjkfg" ascii //weight: 1
        $x_1_3 = "HftgOjhn" ascii //weight: 1
        $x_1_4 = "RdrcfvtIhnuBgy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BC_2147745407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BC!MTB"
        threat_id = "2147745407"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 14 32 0f b6 04 08 03 c2 99 f7 fb 8b 45 ?? 03 d7 03 55 ?? 8a 14 02 8b 45 ?? 30 10 ff 45 ?? 8b 45 ?? 3b 45 ?? 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BF_2147745417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BF!MTB"
        threat_id = "2147745417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 88 04 ?? 40 3d 03 84 01 00 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 03 84 01 00 03 c3 99 f7 f9 8b da}  //weight: 1, accuracy: High
        $x_1_3 = {6a 40 6a 4d 6a 41 68 00 00 80 00 68 ?? ?? ?? ?? 68 [0-6] ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_ARC_2147745428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.ARC!MSR"
        threat_id = "2147745428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PittBull's Directory Watchdog" wide //weight: 1
        $x_1_2 = "This tool is fucking freeware !!!" wide //weight: 1
        $x_1_3 = "Copy me - I want to travel 'round the world..." wide //weight: 1
        $x_1_4 = "AfxOldWndProc423" ascii //weight: 1
        $x_1_5 = "rcOOobhKjnRKfBtDJxBSTroidU" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_K_2147745433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.K!MTB"
        threat_id = "2147745433"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Advance File Splitter\\msp" ascii //weight: 1
        $x_1_2 = "msp_german.dll" ascii //weight: 1
        $x_1_3 = "msp_spanish.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BK_2147745480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BK!MTB"
        threat_id = "2147745480"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d0 0a 44 24 ?? f6 d2 f6 d1 0a d1 22 d0 8b 44 24 ?? 88 10 83 c0 01 83 6c 24 ?? 01 89 44 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BK_2147745480_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BK!MTB"
        threat_id = "2147745480"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 03 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 00 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {68 73 10 00 00 a1 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f be 14 01 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 0f be 08 03 ca 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 88 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_ARD_2147745491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.ARD!MSR"
        threat_id = "2147745491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CryptUnprotectData" ascii //weight: 1
        $x_1_2 = "Drop bomb (poop):" ascii //weight: 1
        $x_1_3 = "owner dead" ascii //weight: 1
        $x_1_4 = "broken pipe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CF_2147745554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CF!MTB"
        threat_id = "2147745554"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e2 ff 00 00 00 b8 01 00 00 00 c1 e0 00 8b 4d 10 0f b6 04 01 8b 4d fc 33 04 91 ba 01 00 00 00 c1 e2 00 8b 4d 14 88 04 11 8b 55 f8 83 c2 01 81 e2 ff 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 08 85 c9 74 ?? 8b 55 ?? c1 ea 0d 8b 45 ?? c1 e0 13 0b d0 89 55 ?? 8b 4d ?? 0f b6 11 83 fa 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_L_2147745600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.L!MTB"
        threat_id = "2147745600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 10 00 00 8d 54 24 24 52 6a 00 8d 44 24 24 50 ff d3 50 ff d5 8b 4c 24 60 8b 54 24 5c 8b 44 24 14 51 52 50 ff d7}  //weight: 1, accuracy: High
        $x_1_2 = {41 81 e1 ff 00 00 00 8b 54 88 08 03 f2 81 e6 ff 00 00 00 8b 5c b0 08 89 5c 88 08 03 da 89 54 b0 08 81 e3 ff 00 00 00 8a 54 98 08 32 55 00 83 6c 24 14 01 88 17 0f 85 65 fe ff ff 5f 89 70 04 5e 5d 89 08 5b c3}  //weight: 1, accuracy: High
        $x_1_3 = {ff 54 24 3c 8b 44 24 60 8b 4c 24 5c 8b 54 24 14 2f 00 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 52 50 8d 4c 24 24 51 6a 00 8d 54 24 24 52 ff d5 50 ff 54 24 3c 8b 44 24 60 8b 4c 24 5c 8b 54 24 14 50 51 52 ff d3}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 4c 24 6c 8b 44 24 20 83 c4 0c 51 8b 4c 24 24 8d 54 24 64 52 50 6a 00 6a 01 6a 00 51 ff 54 24 64 8b 4c 24 14 5f f7 d8 5e 1b c0 5d 23 c1 5b 83 c4 48 c3}  //weight: 1, accuracy: High
        $x_1_5 = {8b 8c 24 94 00 00 00 8b 44 24 48 83 c4 34 51 8b 4c 24 24 8d 54 24 64 52 50 6a 00 6a 01 6a 00 51 ff 54 24 64 5f f7 d8 5e 1b c0 23 44 24 0c 5d 5b 83 c4 48 c3}  //weight: 1, accuracy: High
        $x_1_6 = {8b 44 24 6c 8b 54 24 20 83 c4 0c 50 8b 44 24 24 8d 4c 24 64 51 52 6a 00 6a 01 6a 00 50 ff 54 24 64 5f f7 d8 5e 1b c0 23 44 24 0c 5d 5b 83 c4 48 c3}  //weight: 1, accuracy: High
        $x_1_7 = "UnhandledExceptionFilter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Emotet_DHN_2147745623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DHN!MTB"
        threat_id = "2147745623"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 0c 53 56 57 a1 ?? ?? ?? ?? 33 c5 50 8d 45 f4 64 a3 00 00 00 00 89 65 f0 8b f9 89 7d ec 8b 45 08 8b f0 83 ce 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d6 6a 00 6a 00 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 6a 00 ff d6}  //weight: 1, accuracy: High
        $x_1_3 = "0TrS0as$5WvPaj~" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Emotet_DHU_2147745624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DHU!MTB"
        threat_id = "2147745624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 f9 61 0f be c9 7c 03 83 e9 20 03 ?? 8a ?? ?? ?? 84 c9 75 e1 0a 00 8b ?? c1 ?? 13 c1 ?? 0d 0b}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 5c 8b 4c 24 58 8b 54 24 14 50 51 52 ff d7 8b 44 24 68 8b 54 24 20 83 c4 0c ?? ?? ?? ?? ?? ?? ?? ?? ?? 51 52 6a 00 6a 01 6a 00 50 ff 54 24 60 8b 4c 24 14}  //weight: 1, accuracy: Low
        $x_1_3 = {80 f9 61 0f b6 c9 72 03 83 e9 20 03 ?? ?? 8a ?? 84 c9 75 e2 0a 00 8b ?? c1 ?? 13 c1 ?? 0d 0b}  //weight: 1, accuracy: Low
        $x_1_4 = {83 c4 40 ff 35 ?? ?? ?? ?? 8d 45 f0 ff 35 ?? ?? ?? ?? 50 53 8d 45 f8 50 ff 55 bc 50 ff 55 b8 ff 75 0c ff 75 08 ff 75 f8 ff 55 d8 57 56}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Emotet_DHV_2147745625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DHV!MTB"
        threat_id = "2147745625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 c8 0d 80 f9 61 0f b6 c9 72 03 83 e9 20 03 c1 42 8a 0a 84 c9 75 e9}  //weight: 1, accuracy: High
        $x_1_2 = {6a 40 68 00 10 00 00 8d 45 f0 50 56 8d 45 f8 50 ff 55 bc 50 ff 55 b8 ff 75 0c ff 75 08 ff 75 f8 ff 55 d8 83 c4 0c ff 75 0c 8d 45 0c 50 ff 75 f8 56 6a 01 56 ff 75 ec ff 55 dc f7 d8 1b c0 23 45 f8}  //weight: 1, accuracy: High
        $x_1_3 = {83 c4 40 ff 35 ?? ?? ?? ?? 8d 45 f0 ff 35 ?? ?? ?? ?? 50 53 8d 45 f8 50 ff 55 bc 50 ff 55 b8 ff 75 0c ff 75 08 ff 75 f8 ff 55 d8 57 56}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Emotet_DHT_2147745630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DHT!MTB"
        threat_id = "2147745630"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 ec 10 8b 4d 08 8b 41 10 56 8b 75 0c 57 8b fe 2b 79 0c 83 c6 fc c1 ef 0f 8b cf 69 c9 04 02 00 00 8d 8c 01 44 01 00 00 89 4d f0}  //weight: 1, accuracy: High
        $x_1_2 = "}b{67KB0k1HF6ywyKu7w05V4KqGwt#KC" wide //weight: 1
        $x_1_3 = "RT7s$rRwtX~kd#tH6{$2pIC28O9}f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Emotet_AL_2147745677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AL!MSR"
        threat_id = "2147745677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DlgSmpl.Document" wide //weight: 1
        $x_1_2 = "MPADVFN.DLL" wide //weight: 1
        $x_1_3 = "c:\\Users\\User\\Desktop\\2005\\DlgSmpl\\WinRel\\DlgSmpl.pdb" ascii //weight: 1
        $x_1_4 = "%s\\shell\\open\\%s" ascii //weight: 1
        $x_1_5 = "DlgSmpl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CG_2147745736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CG!MTB"
        threat_id = "2147745736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c0 b9 02 68 00 00 2b c8 89 0d ?? ?? ?? ?? 83 c4 14 b9 01 10 00 00 2b c8 89 0d ?? ?? ?? ?? 6a 41 59 2b c8 89 0d ?? ?? ?? ?? 6a 02 59 2b c8 89 0d ?? ?? ?? ?? b9 04 80 00 00 2b c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DHZ_2147745842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DHZ!MTB"
        threat_id = "2147745842"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 23 fb 8b 54 b8 08 03 ea 23 eb 8b 5c a8 08 89 5c b8 08 89 54 a8 08 03 da 23 1d ?? ?? ?? ?? 8a 54 98 08 32 16 88 11}  //weight: 1, accuracy: Low
        $x_1_2 = {8b ea c1 e5 13 c1 ea 0d 0b d5 80 f9 61 0f b6 c9 72 03 83 e9 20 03 d1 8a 48 01 40 84 c9 75 e1}  //weight: 1, accuracy: High
        $x_1_3 = {8b 55 fc 89 54 98 08 8b 5d f8 03 da 23 1d ?? ?? ?? ?? 8a 54 98 08 32 16 8b 5d 08 88 11}  //weight: 1, accuracy: Low
        $x_1_4 = {8b f0 c1 e6 13 c1 e8 0d 0b c6 80 f9 61 0f b6 c9 72 03 83 e9 20 03 c1 42 8a 0a 84 c9 75 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Emotet_CI_2147745851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CI!MTB"
        threat_id = "2147745851"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 ff d6 55 e8 ?? ?? ?? ?? 8b c8 33 d2 8b c7 f7 f1 8a 04 1f 83 c4 04 8a 54 55 00 32 c2 88 04 1f 8b 44 24 1c 47 3b f8 75}  //weight: 1, accuracy: Low
        $x_1_2 = {53 8b 5c 24 10 57 8b 7c 24 18 53 e8 ?? ?? ?? ?? 8b c8 33 d2 8b c6 f7 f1 46 83 c4 04 8a 14 53 30 54 3e ff 3b f5 75}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 0a 8b 8d 50 ff ff ff e8 ?? ?? ?? ?? 8b 8d 50 ff ff ff e8 c6 06 00 00 8b 45 fc 33 d2 b9 27 00 00 00 f7 f1 8b 45 08 0f b7 0c 50 8b 55 0c 03 55 fc 0f b6 02 33 c1 8b 4d 0c 03 4d fc 88 01 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DAA_2147745996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DAA!MTB"
        threat_id = "2147745996"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c6 2b c2 d1 e8 03 c2 8b 54 24 14 c1 e8 05 6b c0 23 8b ce 2b c8 8a 04 4a 30 04 1e}  //weight: 1, accuracy: High
        $x_1_2 = {8d 0c 07 33 d2 6a 23 8b c7 5b f7 f3 8b 44 24 10 8a 04 50 30 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DAB_2147745997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DAB!MTB"
        threat_id = "2147745997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 8b c1 bd 36 00 00 00 f7 f5 8a 04 53 30 04 31 41 3b cf 75 ea}  //weight: 1, accuracy: High
        $x_1_2 = {8b c6 2b c2 d1 e8 03 c2 8b 54 24 14 c1 e8 05 6b c0 36 8b ce 2b c8 8a 04 4a 30 04 1e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_CJ_2147746128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CJ!MTB"
        threat_id = "2147746128"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 08 03 55 f0 0f b6 02 8b 4d fc 03 4d ec 0f b6 d1 0f b6 8c 15 90 fc ff ff 33 c1 8b 55 08 03 55 f0 88 02 e9}  //weight: 1, accuracy: High
        $x_1_2 = {89 45 fc 8b 4d f8 03 4d fc 81 e1 ff 00 00 00 89 4d f8 8b 55 f8 0f b6 84 15 90 fc ff ff 89 45 ec 8b 4d f4 8a 55 ec 88 94 0d 90 fc ff ff 8b 45 f8 8a 4d fc 88 8c 05 90 fc ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DHW_2147746132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DHW!MTB"
        threat_id = "2147746132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 ec 8b 4d e8 89 0c 90 8b 55 e8 03 55 f0 81 e2 ff 00 00 00 8b 45 10 0f b6 08 8b 45 ec 33 0c 90 8b 55 14 88 0a}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 fc c1 ea 0d 8b 45 fc c1 e0 13 0b d0 89 55 fc 8b 4d 08 0f b6 11 83 fa 61 7c 0e 8b 45 08 0f b6 08 83 e9 20 89 4d f8 eb 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DHX_2147746133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DHX!MTB"
        threat_id = "2147746133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 5d fc 03 da 23 d8 8a 54 99 08 8b 5d 08 32 57 01 88 56 01}  //weight: 2, accuracy: High
        $x_1_2 = {8b f0 c1 e6 13 c1 e8 0d 0b c6 80 f9 61 0f b6 c9 72 03 83 e9 20 03 c1 8a 4a 01 42 84 c9 75 e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DHY_2147746134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DHY!MTB"
        threat_id = "2147746134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5c b0 08 89 5c 88 08 89 54 b0 08 03 da 81 e3 ?? ?? ?? ?? 0f b6 54 98 08 32 55 00 41 88 17 81 e1 00 8b 54 88 08 03 f2 81 e6 ff 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 c8 0d 80 f9 61 0f b6 c9 72 03 83 e9 20 42 03 c1 8a 0a 84 c9 75 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DAC_2147746136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DAC!MTB"
        threat_id = "2147746136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c7 01 81 e7 ?? ?? ?? ?? 0f b6 44 3c 1c 03 e8 81 e5 00 0f b6 5c 2c 1c 6a 00 88 5c 3c 20 6a 00 89 44 24 18 88 44 2c 24 ff 15 ?? ?? ?? ?? 02 5c 24 10 83 c6 01 0f b6 c3 8a 4c 04 1c 8b 44 24 18 30 4c 30 ff 3b b4 24 74 03 00 00 7c b0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_M_2147746165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.M!MTB"
        threat_id = "2147746165"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {f7 e9 03 d1 8b 8c fe 14 07 00 00 c1 fa 0e 8b c2 c1 e8 1f 03 c2 4b 8b ac c6 14 07 00 00 8b 94 fe 18 07 00 00 89 ac fe 14 07}  //weight: 10, accuracy: High
        $x_3_2 = "DllRegisterServer" ascii //weight: 3
        $x_3_3 = "ha1me5i" ascii //weight: 3
        $x_3_4 = "tbbI7r27dcl2M" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_M_2147746165_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.M!MTB"
        threat_id = "2147746165"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 00 6a 00 ff d7 6a 00 6a 00 ff d7 6a 00 6a 00 ff d7 8b 4c 24 14 b8 ?? ?? ?? ?? f7 e6 c1 ea 05 6b d2 2e 8b c6 2b c2 8a 14 41 30 14 1e 83 c6 01 3b f5 75 cc}  //weight: 5, accuracy: Low
        $x_5_2 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 55 08 03 55 f0 0f b6 02 8b 4d fc 03 4d ec 0f b6 d1 0f b6 8c 15 ?? ?? ff ff 33 c1 8b 55 08 03 55 f0 88 02 e9 ?? ff ff ff 8b 4d e4 33 cd e8 ?? ?? ?? ?? 8b e5 5d c3}  //weight: 5, accuracy: Low
        $x_5_3 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 55 08 03 55 ec 33 c0 8a 02 8b 4d fc 03 4d f8 81 e1 ff 00 00 00 33 d2 8a 94 0d ?? ?? ff ff 33 c2 8b 4d 08 03 4d ec 88 01 e9 ?? ?? ff ff 8b e5 5d c3}  //weight: 5, accuracy: Low
        $x_5_4 = {6a 00 6a 00 ff d6 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 02 5c 24 14 8b 44 24 18 0f b6 d3 8a 4c 14 1c 30 0c 38 47 3b bc 24 ?? ?? 00 00 0f 8c ?? ff ff ff}  //weight: 5, accuracy: Low
        $x_5_5 = {45 33 c9 81 e5 fe 01 00 00 33 c0 8a 4c 2c 10 03 d9 81 e3 fe 01 00 00 8a 44 1c 10 88 44 2c 10 02 c1 25 ff 00 00 00 88 4c 1c 10 8a 0c 32 8a 44 04 10 32 c8 88 0c 32 42 3b d7 7c c5}  //weight: 5, accuracy: High
        $x_5_6 = {ff d6 57 57 ff d6 02 5d f8 8b 4d fc 8b 45 08 0f b6 d3 8a 94 15 c4 fe ff ff 03 c1 30 10 41 3b 4d 0c 89 4d fc 0f 8c ?? ff ff ff}  //weight: 5, accuracy: Low
        $x_1_7 = {8b 54 24 1c 52 56 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 18 ff d6 39 7c 24 4c 72 0d 8b 44 24 38 50 e8 ?? ?? ?? ?? 83 c4 04 8b 4c 24 54 64 89 0d 00 00 00 00 59 5f 5e 5b}  //weight: 1, accuracy: Low
        $x_1_8 = {8b 55 f8 52 8b 45 ec 50 8b 4d e0 51 e8 ?? ?? ?? ?? 83 c4 10 8b 55 e0 89 55 fc ff 55 fc 89 45 e8 6a 00 ff 15 ?? ?? ?? ?? 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_9 = {8b 45 f0 50 8b 4d fc 51 8b 55 d8 52 e8 ?? ?? ?? ?? 83 c4 10 8b 45 d8 89 45 e8 ff 55 e8 89 45 ec 6a 00 ff 15 ?? ?? ?? ?? 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_10 = {6a 40 68 00 30 00 00 56 6a 00 53 ff d0 56 8b f8 55 57 e8 ?? ?? ?? ?? 83 c4 0c 6a ?? 68 ?? ?? ?? ?? 56 57 e8 ?? ?? ?? ?? 83 c4 10 ff d7}  //weight: 1, accuracy: Low
        $x_1_11 = {8b 44 24 14 53 6a 40 68 00 30 00 00 50 53 56 ff d7}  //weight: 1, accuracy: High
        $x_1_12 = {ff 75 fc 53 e8 ?? ?? ff ff 83 c4 10 ff d3 57 ff 15 ?? ?? ?? 00 5f 5e 5b c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_CK_2147746171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CK!MTB"
        threat_id = "2147746171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d1 81 e2 ff 00 00 00 0f b6 5c 14 ?? 89 54 24 ?? 8d 54 14 ?? 6a 00 88 18 6a 00 89 4c 24 ?? 88 0a ff 15 ?? ?? ?? ?? 8a 44 24 ?? 8a 14 3e 02 d8 0f b6 c3 8a 4c 04 ?? 32 d1 88 14 3e 46 3b f5 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DAD_2147746189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DAD!MTB"
        threat_id = "2147746189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 2b c2 d1 e8 03 c2 8b 54 24 14 c1 e8 05 6b c0 ?? 8b ce 2b c8 8a 04 4a 30 04 1e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DAE_2147746190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DAE!MTB"
        threat_id = "2147746190"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d1 81 e2 ff 00 00 00 0f b6 5c 14 1c 89 54 24 10 8d 54 14 1c 6a 00 88 18 6a 00 89 4c 24 20 88 0a ff 15 ?? ?? ?? ?? 8a 44 24 18 8a 14 3e 02 d8 0f b6 c3 8a 4c 04 1c 32 d1 88 14 3e 46 3b f5 7c a4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DAF_2147746198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DAF!MTB"
        threat_id = "2147746198"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 0f b6 94 3d ?? ?? ?? ?? 8d 84 3d 00 03 ca 23 ce 89 55 10 89 4d f0 0f b6 9c 0d 00 8d 8c 0d 00 88 18 88 11 ff 15 ?? ?? ?? ?? 02 5d 10 8b 45 08 8b 4d fc 0f b6 d3 03 c1 8a 94 15 00 30 10 41 3b 4d 0c 89 4d fc 7c a4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CL_2147746224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CL!MTB"
        threat_id = "2147746224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 08 83 c4 0c 33 d2 84 c9 74 ?? 8b ea c1 e5 13 c1 ea 0d 0b d5 80 f9 61 0f b6 c9 72 ?? 83 e9 20 03 d1 8a 48 01 40 84 c9 75}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 ff 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 03 80 00 00 c7 05 ?? ?? ?? ?? 01 68 00 00 c7 05 ?? ?? ?? ?? 01 00 00 00 c7 05 ?? ?? ?? ?? 40 00 00 00 c7 05 ?? ?? ?? ?? 00 10 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CM_2147746260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CM!MTB"
        threat_id = "2147746260"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {03 c8 2b 4d f0 2b 4d ec 8b 75 d0 0f af 75 f0 03 4d cc 03 f1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CM_2147746260_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CM!MTB"
        threat_id = "2147746260"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 ff d6 6a 00 6a 00 ff d6 6a 00 6a 00 ff d6 02 5c 24 ?? 83 c7 01 0f b6 c3 8a 4c 04 1c 8b 44 24 ?? 30 4c 38 ff 3b bc 24 ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
        $x_1_2 = {8d a4 24 00 00 00 00 8b ff 8b 5c 24 10 83 c5 01 81 e5 ff 00 00 00 0f b6 44 2c 1c 8d 0c 18 81 e1 ff 00 00 00 0f b6 5c 0c 1c 89 4c 24 10 8d 4c 0c 1c 6a 00 88 5c 2c 20 6a 00 89 44 24 1c 88 01 ff d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AB_2147746282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AB!MTB"
        threat_id = "2147746282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 54 24 2c 8d 04 0a 99 b9 69 7a 00 00 f7 f9 8b 6c 24 54 2b 54 24 14 8b ca 8b 54 24 30 0f b6}  //weight: 1, accuracy: High
        $x_1_2 = {99 bd 69 7a 00 00 f7 fd 8b 44 24 54 8b 6c 24 18 83 c5 01 89 6c 24 18 03 d7 03 d6 0f b6 14 02}  //weight: 1, accuracy: High
        $x_1_3 = "p!c!X8<0aiR1>fkdymE<X!!xfdtZ?<*&nJxRZz9Voy!&q3*ITkF57r@_EaCLz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_AB_2147746282_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AB!MTB"
        threat_id = "2147746282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "&hAovTFlw+f3UFA#)!yRsfOEek#SN?uni821" ascii //weight: 3
        $x_3_2 = "PostQuitMessage" ascii //weight: 3
        $x_3_3 = "PostMessageW" ascii //weight: 3
        $x_3_4 = "NoNetConnectDisconnect" ascii //weight: 3
        $x_3_5 = "NoRecentDocsHistory" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AB_2147746282_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AB!MTB"
        threat_id = "2147746282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f1 ed b5 77 61 89 45 ?? 8b 45 ?? 8b 55 ?? 8a 1c 02 8b 45 ?? 88 5d ?? 39 c8 74}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 14 01 8b 75 ?? 88 14 06 83 c0 01 8b 7d ?? 39 f8 89 45 ?? 75 06 00 8b 45 ?? 8b 4d f0}  //weight: 1, accuracy: Low
        $x_1_3 = {81 f1 fb 0d eb 6e 8b 55 ?? 8a 1c 02 8b 75 ?? 88 1c 06 01 c8 8b 4d ?? 39 c8 89 45 ?? 74}  //weight: 1, accuracy: Low
        $x_1_4 = {8a 1c 02 8b 44 24 ?? 88 1c 08 8b 4c 24 ?? 83 c1 01 89 4c 24 ?? 8b 74 24 ?? 39 f1 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_AB_2147746290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AB!MSR"
        threat_id = "2147746290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AfxFrameOrView70s" ascii //weight: 1
        $x_1_2 = "AfxOleControl70s" ascii //weight: 1
        $x_1_3 = "c:\\Users\\User\\Desktop\\2003\\Accel\\Release\\Accel.pdb" ascii //weight: 1
        $x_1_4 = "%s\\shell\\open\\%s" ascii //weight: 1
        $x_1_5 = "stem32\\cmd." ascii //weight: 1
        $x_1_6 = "RYPT32.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DAG_2147747694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DAG!MTB"
        threat_id = "2147747694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 f2 81 e6 ff 00 00 00 8b 5c b0 08 89 5c 88 08 89 54 b0 08 03 da 81 e3 ff 00 00 00 0f b6 54 98 08 32 55 00 83 c1 01 88 17}  //weight: 1, accuracy: High
        $x_1_2 = {c1 c8 0d 80 f9 61 0f b6 c9 72 03 83 e9 20 83 c2 01 03 c1 8a 0a 84 c9 75 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DAH_2147747695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DAH!MTB"
        threat_id = "2147747695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 6a 00 6a 00 ff 15 00 6a 00 6a 00 ff 15 00 6a 00 6a 00 ff 15 00 6a 00 6a 00 ff 15 00 6a 00 6a 00 ff 15 00 6a 00 6a 00 ff 15 00 8b 55 08 03 55 f0 0f b6 02 8b 4d fc 03 4d ec 0f b6 d1 0f b6 8c 15 ?? ?? ?? ?? 33 c1 8b 55 08 03 55 f0 88 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DAI_2147747834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DAI!MTB"
        threat_id = "2147747834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 6a 00 6a 00 ff 15 00 6a 00 6a 00 ff 15 00 6a 00 6a 00 ff 15 00 6a 00 6a 00 ff 15 00 8b 55 08 03 55 ec 33 c0 8a 02 8b 4d fc 03 4d f8 81 e1 ff 00 00 00 33 d2 8a 94 0d ?? ?? ?? ?? 33 c2 8b 4d 08 03 4d ec 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 00 ff d6 6a 00 6a 00 ff d6 6a 00 6a 00 ff d6 6a 00 6a 00 ff d6 6a 00 6a 00 ff d6 02 5c 24 14 8b 44 24 18 0f b6 d3 8a 4c 14 1c 30 0c 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_GB_2147747841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GB!MTB"
        threat_id = "2147747841"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 4d fc 8b 55 08 c7 45 fc 75 e4 00 00 c1 6d fc 09 83 75 fc 62 d3 e2 8a 4d fc}  //weight: 1, accuracy: High
        $x_1_2 = "Control_RunDLL" ascii //weight: 1
        $x_1_3 = "RunDLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GB_2147747841_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GB!MTB"
        threat_id = "2147747841"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b c8 03 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 2b c8 2b 0d ?? ?? ?? ?? 8b 45 08 0f b6 0c 08 8b 45 0c 0f b6 14 10 33 d1 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 35}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GB_2147747841_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GB!MTB"
        threat_id = "2147747841"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 17 14 78 72 89 [0-3] e8 [0-4] 68 db 49 35 93 89 [0-3] e8 [0-4] 68 ce 08 01 4e 89 [0-3] e8 [0-4] 68 ab 5e c3 4d 8b ?? e8 [0-4] 68 94 24 8e 94 89 [0-3] e8 [0-4] 68 a3 ca 26 af 8b ?? e8 [0-4] 68 a7 91 44 c9 8b ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c4 89 44 [0-25] f3 ?? 68 15 5b 04 71 [0-2] e8 [0-4] 68 20 e6 3c 0b 8b ?? e8 [0-4] 68 73 e1 88 9f 8b ?? e8 [0-4] 68 20 f6 3c 14 8b ?? e8}  //weight: 1, accuracy: Low
        $x_1_3 = {51 52 6a 00 6a 01 6a 00 50 ff [0-3] 5f f7 d8 5e 1b c0 23 [0-3] 5d 5b 83 c4 ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CN_2147747851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CN!MTB"
        threat_id = "2147747851"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 ff d6 6a 00 6a 00 ff d6 6a 00 6a 00 ff d6 6a 00 6a 00 ff d6 02 5c 24 ?? 8b 84 24 ?? ?? ?? ?? 0f b6 cb 8a 1c 07 8a 54 0c ?? 32 da 88 1c 07 8b 84 24 ?? ?? ?? ?? 47 3b f8 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DAK_2147747900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DAK!MTB"
        threat_id = "2147747900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 44 24 18 02 c3 0f b6 c8 8a 54 0c 1c 8b 44 24 10 8b 8c 24 ?? ?? ?? ?? 30 14 08 8b 8c 24 ?? ?? ?? ?? 40 3b c1 89 44 24 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_2147747909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet!ibt"
        threat_id = "2147747909"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f0 83 c0 01 89 45 f0 81 7d f0 a5 02 00 00 7d 0f 8b 4d f0 8a 55 f0 88 94 0d 38 fd ff ff eb df c7 45 f0 00 00 00 00 eb 09 8b 45 f0 83 c0 01 89 45 f0 81 7d f0 a5 02 00 00 7d 63 8b 4d f0 0f b6 94 0d 38 fd ff ff 89 55 fc 8b 85 34 fd ff ff 03 45 fc 8b 4d 10 03 4d e8 0f be 11 03 c2 25 ff 00 00 00 89 85 34 fd ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 55 08 03 55 f0 0f b6 02 8b 4d fc 03 4d ec 0f b6 d1 0f b6 8c 15 38 fd ff ff 33 c1 8b 55 08 03 55 f0 88 02 e9 ce fe ff ff 8b 4d e4 33 cd e8 b2 1e 03 00 8b e5 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DAL_2147747915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DAL!MTB"
        threat_id = "2147747915"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 5c 24 44 8b 45 08 0f b6 cb 8a 1c 06 8a 54 0c 48 32 da 83 c4 30 88 1c 06 8b 45 0c 46 3b f0 0f 8c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CO_2147747962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CO!MTB"
        threat_id = "2147747962"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 64 6a 64 6a 64 6a 64 6a 64 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? dd 05 ?? ?? ?? ?? 83 c4 24 dd 54 24 10 dd 54 24 08 dd 1c 24 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 02 5c 24 6c 8b 44 24 70 0f b6 cb 8a 54 0c 74 30 14 30 83 c4 1c 83 c6 01 3b 75 0c 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CP_2147747966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CP!MTB"
        threat_id = "2147747966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 44 24 3c 8b 6c 24 20 03 d6 8a 04 02 30 45 00 ff 44 24 10}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CP_2147747966_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CP!MTB"
        threat_id = "2147747966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d a4 24 00 00 00 00 47 81 e7 ff 00 00 00 0f b6 54 3c ?? 03 ea 81 e5 ff 00 00 00 0f b6 44 2c ?? 88 44 3c ?? 02 c2 88 54 2c ?? 0f b6 d0 8a 54 14 ?? 8b 44 24 0c 30 14 08 41 3b ce 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PVK_2147748020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PVK!MTB"
        threat_id = "2147748020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 5c 24 10 83 c6 01 0f b6 c3 8a 4c 04 1c 8b 44 24 18 30 4c 30 ff 3b b4 24 54 01 00 00 7c}  //weight: 2, accuracy: High
        $x_2_2 = {8a 02 8b 4d fc 03 4d f8 81 e1 ff 00 00 00 33 d2 8a 94 0d b8 fe ff ff 33 c2 8b 4d 08 03 4d ec 88 01 e9}  //weight: 2, accuracy: High
        $x_2_3 = {8b d7 b8 a8 dd 00 00 8b ca b8 ff 01 00 00 03 c1 2d ff 01 00 00 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 2, accuracy: Low
        $x_2_4 = {8a 4c 10 03 8a d9 8a f9 80 e3 f0 c0 e1 06 0a 4c 10 02 80 e7 fc c0 e3 02 0a 1c 10 c0 e7 04 0a 7c 10 01 81 3d ?? ?? ?? ?? be 00 00 00 88 8d fb fb ff ff}  //weight: 2, accuracy: Low
        $x_2_5 = {8b 55 e4 81 ea e8 03 00 00 89 55 e4 c1 45 8c 07 8b 45 8c 33 45 90 89 45 8c 8b 4d c8 8b 55 f8 8b 45 8c 89 04 8a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_AF_2147748031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AF!MSR"
        threat_id = "2147748031"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AfxControlBar70s" ascii //weight: 1
        $x_1_2 = "AfxMDIFrame70s" ascii //weight: 1
        $x_1_3 = "AfxFrameOrView70s" ascii //weight: 1
        $x_1_4 = "pablovandermeer.nl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_KDS_2147748060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.KDS!MTB"
        threat_id = "2147748060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 44 1c 10 88 44 2c 10 02 c1 25 ff 00 00 00 88 4c 1c 10 8a 0c 32 8a 44 04 10 32 c8 88 0c 32 42 3b d7 7c}  //weight: 2, accuracy: High
        $x_2_2 = {8b 45 18 8b 4d 10 03 08 8b 55 f8 8b 84 11 ?? ?? ff ff 03 45 14 8b 4d 18 8b 55 10 03 11 8b 4d f8 89 84 0a ?? ?? ff ff e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DAM_2147748112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DAM!MTB"
        threat_id = "2147748112"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "EMOTET" ascii //weight: 2
        $x_1_2 = "eGNkZg=" ascii //weight: 1
        $x_1_3 = "Image.bmp" ascii //weight: 1
        $x_1_4 = "C:\\WINDOWS\\SYSTEM32\\CRYPT32.DLL" wide //weight: 1
        $x_2_5 = "EMOTET" wide //weight: 2
        $x_1_6 = "Please enter a currency." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DAN_2147748113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DAN!MTB"
        threat_id = "2147748113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 0a 6a 05 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 02 5c 24 58 83 c6 01 0f b6 c3 8a 4c 04 68 8b 44 24 64 30 4c 30 ff 83 c4 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DAO_2147748114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DAO!MTB"
        threat_id = "2147748114"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c7 01 81 e7 ?? ?? ?? ?? 0f b6 44 3c 1c 03 e8 81 e5 00 0f b6 5c 2c 1c 6a 00 88 5c 3c 20 6a 00 89 44 24 18 88 44 2c 24 ff 15 ?? ?? ?? ?? 02 5c 24 10 8b 44 24 18 0f b6 cb 8a 54 0c 1c 30 14 30 83 c6 01 3b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DAP_2147748115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DAP!MTB"
        threat_id = "2147748115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 53 6a 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 2d 01 52 89 44 24 60 ff d6 8b 6c 24 4c 8b f8 8b 44 24 48 68 01 03 c5 50 57 ff 54 24 78 8b 4c 24 54 8b 54 24 5c 83 c4 0c 53 6a 40 68 00 51 53 52 ff d6 8b f0 8b 44 24 48 50 55 56 ff 54 24 78 8b 54 24 54 6a 27}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualAllocExNuma" ascii //weight: 1
        $x_1_3 = "memcpy" ascii //weight: 1
        $x_1_4 = "CopyFileW" wide //weight: 1
        $x_1_5 = "ShellExecuteW" wide //weight: 1
        $x_1_6 = "CryptStringToBinaryA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_KVD_2147748123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.KVD!MTB"
        threat_id = "2147748123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "D2l%j5gZCLK" wide //weight: 2
        $x_2_2 = "Kd3rgLPUxwa" wide //weight: 2
        $x_2_3 = {8a 4c 24 40 8b 84 24 58 03 00 00 02 d9 83 c4 30 8a 14 06 81 e3 ff 00 00 00 8a 4c 1c 14 32 d1 88 14 06 8b 84 24 2c 03 00 00 46 3b f0}  //weight: 2, accuracy: High
        $x_2_4 = {b8 ed de 18 07 8b 4d e0 8b 55 08 8b 75 ec 81 f6 db de 18 07 01 d6 2b 45 ec 0f b6 0c 31 01 c1 88 cb 88 5d e7}  //weight: 2, accuracy: High
        $x_2_5 = {b9 58 00 00 00 8b 94 24 dc 00 00 00 8a 5c 24 6b 20 db 88 9c 24 f3 00 00 00 81 c2 f9 3e 32 d4 89 e6 89 56 08}  //weight: 2, accuracy: High
        $x_2_6 = {8b 45 c4 8b 4d ec 81 f1 6f a7 da 23 01 c8 89 45 c4 b8 f1 a7 da 23 2b 45 ec 39 45 c4 0f 85}  //weight: 2, accuracy: High
        $x_2_7 = {8b 45 08 8b 4d 10 0f b6 d3 03 c1 8a 94 15 8c fe ff ff 30 10 41 3b 4d 0c 89 4d 10 0f 8c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_CX_2147748460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CX!MTB"
        threat_id = "2147748460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f4 0f b6 0c 10 8b 55 f8 0f b6 84 15 d8 d5 ff ff 33 c1 8b 4d f8 88 84 0d d8 d5 ff ff 50 53 8b c3 2b db 33 c0 2b d8 b8 84 00 00 00 81 f3 ee 00 00 00 2b c3 83 f3 1c 2b d8 83 e8 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DAJ_2147748488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DAJ!MTB"
        threat_id = "2147748488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c8 04 6a 00 50 e8 ?? ?? ?? ?? 8a 44 24 18 8b 4c 24 1c 02 c3 0f b6 d0 8b 44 24 14 8a 54 14 20 30 14 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_O_2147748491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.O!MTB"
        threat_id = "2147748491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "CLSID\\%1\\InProcServer32" ascii //weight: 2
        $x_2_2 = "eGNkZg=" ascii //weight: 2
        $x_2_3 = {4e 6f 52 75 6e [0-16] 4e 6f 44 72 69 76 65 73 [0-16] 52 65 73 74 72 69 63 74 52 75 6e [0-16] 4e 6f 4e 65 74 43 6f 6e 6e 65 63 74 44 69 73 63 6f 6e 6e 65 63 74 [0-16] 4e 6f 52 65 63 65 6e 74 44 6f 63 73 48 69 73 74 6f 72 79 [0-16] 4e 6f 43 6c 6f 73 65}  //weight: 2, accuracy: Low
        $x_2_4 = {43 52 59 50 54 33 32 2e 44 4c 4c 00 43 72 79 70 74 53 74 72 69 6e 67 54 6f 42 69 6e 61 72 79 41}  //weight: 2, accuracy: High
        $x_1_5 = {4b 00 45 00 52 00 4e 00 45 00 4c 00 33 00 32 00 2e 00 44 00 4c 00 4c 00 00 00 00 00 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 4e 75 6d 61}  //weight: 1, accuracy: High
        $x_1_6 = {4b 00 45 00 52 00 4e 00 45 00 4c 00 33 00 32 00 2e 00 44 00 4c 00 4c 00 00 00 00 00 44 65 63 6f 64 65 50 6f 69 6e 74 65 72}  //weight: 1, accuracy: High
        $x_5_7 = {6a 40 68 00 30 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_DAR_2147748576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DAR!MTB"
        threat_id = "2147748576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 10 83 c4 04 6a 00 6a 00 89 01 ff 15 ?? ?? ?? ?? 8b 54 24 0c 8b 02 6a 00 6a 00 56 50 6a 01 55 53 ff d7 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 1c 83 c4 0c 6a 00 6a 40 68 00 30 00 00 50 6a 00 56 ff d5 8b 4c 24 10 51 8b f0 53 56 ff ?? ?? ?? 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DAQ_2147748645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DAQ!MTB"
        threat_id = "2147748645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 89 03 ff d6 6a 00 6a 00 ff d6 6a 00 6a 00 ff d6 8b 13 8b 44 24 20 6a 00 6a 00 57 52 6a 01 50 55 ff 15 ?? ?? ?? ?? 5e 5b 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DAS_2147748646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DAS!MTB"
        threat_id = "2147748646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 56 6a 00 6a 01 55 8b f8 53 ff d7 85 c0 8b 06 [0-3] 50 e8 ?? ?? ?? ?? 8b 4c 24 ?? 83 c4 04 6a 00 6a 00 56 50 6a 01 55 53 89 01 ff d7 5f 5e}  //weight: 1, accuracy: Low
        $x_1_2 = {68 e0 07 00 00 03 ca 51 50 89 44 24 ?? ff d7 8b 44 24 ?? 83 c4 0c 6a 00 6a 40 68 00 30 00 00 50 6a 00 55 ff d3 8b ?? ?? ?? ?? ?? ?? ?? 51 8b f0 52 56 ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DAT_2147748647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DAT!MTB"
        threat_id = "2147748647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 30 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 89 44 24 ?? ff d6 8b f0 56 6a 00 ff 54 24 ?? 56 6a 00 89 44 24 ?? ff 54 24 ?? 8b f0 8b 44 24 ?? 50 ff 54 24}  //weight: 1, accuracy: Low
        $x_1_2 = {68 e0 07 00 00 6a 00 57 ff d3 8b 54 24 ?? 68 e0 07 00 00 03 d6 8b f8 52 57 ff d5 [0-10] 83 c4 0c 6a 00 50 68 00 30 00 00 56 6a 00 51 ff d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_S_2147748743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.S!MTB"
        threat_id = "2147748743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e0 8a 0c 05 ?? ?? ?? ?? 8b 55 ec 8b 75 dc 8a 2c 32 28 cd 8b 7d e8 88 2c 37 83 c6 01 8b 5d f0 39 de 89 75 e4 73}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 d8 8a 0c 05 ?? ?? ?? ?? 8b 55 e8 8b 75 dc 8a 2c 32 28 cd 8b 7d e4 88 2c 37 83 c6 01 8b 5d ec 39 de 89 75 e0 72}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 dc 8b 4d d8 ba ?? ?? ?? ?? 89 45 d4 31 f6 89 55 d0 89 f2 8b 75 d0 f7 f6 8b 7d d4 83 e7 03 83 f9 02 0f 47 fa 8a 1c 3d ?? ?? ?? ?? 8b 55 ec 8b 7d d4 8a 3c 3a 28 df 01 f9 8b 55 e8 88 3c 3a 83 c7 ?? 8b 55 f0 39 d7 89 4d d8 89 7d dc 72 b0}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 7d cc 01 cf 89 4d c4 8b 4d e8 89 55 c0 8b 55 c4 8a 0c 11 8b 55 cc 39 f2 8b 75 c0 0f 47 de 2a 0c 1d ?? ?? ?? ?? 8b 75 e4 8b 5d c4 88 0c 1e 83 c3 33 8b 4d ec 39 cb 89 5d d4 89 7d d0 72}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 45 d4 8b 4d d0 ba ?? ?? ?? ?? 89 45 cc 89 c8 31 f6 89 55 c8 89 f2 8b 75 c8 f7 f6 89 cf 83 e7 03 8b 5d e8 8a 1c 0b 8b 75 cc 83 fe 02 0f 47 fa 01 ce 2a 1c 3d 97 41 40 00 8b 55 e4 88 1c 0a 83 c1 33 8b 7d ec 39 f9 89 75 d4 89 4d d0 72 b1}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 45 ec 8b 4d b8 8a 14 01 8b 45 ec 03 45 dc 8b 75 e8 8a 75 c3 f6 c6 01 0f 44 75 c4 8a 34 35 ?? ?? ?? ?? 8b 75 ec 28 f2 8b 7d b4 88 14 37 8b 75 ec 83 c6 33 89 45 e4 89 45 e0 89 75 cc 8b 45 bc 39 c6 0f 82 ?? ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Emotet_DAW_2147749121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DAW!MTB"
        threat_id = "2147749121"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e1 c1 ea ?? 8b c2 c1 e0 ?? 2b c2 03 c0 03 c0 8b d1 2b d0 8a 44 14 ?? 30 04 39 83 c1 01 81 f9 e0 07 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DAX_2147749122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DAX!MTB"
        threat_id = "2147749122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e1 d1 ea 6b d2 ?? 8b c1 2b c2 8a 54 04 ?? 30 14 39 83 c1 01 81 f9 e0 07 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 e1 c1 ea ?? 6b d2 ?? 8b c1 2b c2 8a 14 18 30 14 31 83 c1 01 3b cf 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_VDS_2147749127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.VDS!MTB"
        threat_id = "2147749127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c3 c1 e8 05 03 45 88 8b cb c1 e1 04 03 4d 8c 33 c1 8b 4d 98 03 cb 33 c1 2b f8 81 7d a4 61 0e 00 00 73}  //weight: 2, accuracy: High
        $x_2_2 = {8b ff 69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b d1 c1 ea 10 30 14 38 40 3b c6 7c}  //weight: 2, accuracy: High
        $x_2_3 = {33 c5 89 45 fc c7 05 ?? ?? ?? ?? 30 5a 0a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 c8 89 0d 05 00 a1}  //weight: 2, accuracy: Low
        $x_2_4 = {8b ca b8 ff 01 00 00 03 c1 2d ff 01 00 00 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_RZ_2147749139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RZ!MSR"
        threat_id = "2147749139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 81 8c 00 00 00 83 c7 01 03 54 24 20 03 34 90 b8 56 55 55 55 f7 ee 8b c2 c1 e8 1f 03 c2 8b b4 81 c4 00 00 00 8b 44 24 10 8b 91 00 05 00 00 89 34 10 83 c0 04 3b b9 cc 04 00 00 89 44 24 10 0f 8c 75 ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {8b c8 c1 e1 08 0b c8 c1 e1 08 81 c9 ff 00 00 00 83 c6 01 89 0f 83 c7 04 81 fe 00 01 00 00 89 74 24 3c 7c b0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_QA_2147749587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.QA"
        threat_id = "2147749587"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 13 68 01 00 01 00 ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {00 75 f0 51 e8 31 00 b8 ?? ?? ?? ?? a3 ?? ?? ?? ?? a3 ?? ?? ?? ?? 33 c0 21 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 39 05 ?? ?? ?? ?? 74 18 40 a3 ?? ?? ?? ?? 83 3c c5}  //weight: 1, accuracy: Low
        $x_1_3 = {02 03 01 00 01 00 00 65 00 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DAY_2147749649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DAY!MTB"
        threat_id = "2147749649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 8b 5c 24 ?? 55 8b 6c 24 ?? 56 8b 74 24 ?? 8b c1 33 d2 f7 f3 8a 44 55 00 8a 14 31 32 d0 88 14 31 41 3b cf 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DAZ_2147749650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DAZ!MTB"
        threat_id = "2147749650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 8b 5c 24 ?? 55 8b 6c 24 ?? 56 8b 74 24 ?? 8d 9b 00 00 00 00 8b c1 33 d2 f7 f3 83 c1 01 8a 44 55 00 30 44 31 ff 3b cf 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DBA_2147749651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DBA!MTB"
        threat_id = "2147749651"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 0c 33 d2 8d 0c 06 8b c6 f7 75 ?? 8b 45 ?? 8a 04 50 30 01 46 3b 75 10 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DBB_2147749694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DBB!MTB"
        threat_id = "2147749694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff d7 8b c6 33 d2 f7 f5 8b 44 24 ?? 8a 0c 50 8a 14 1e 8b 44 24 ?? 32 d1 88 14 1e 46 3b f0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DBC_2147749733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DBC!MTB"
        threat_id = "2147749733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 8b 5c 24 ?? 55 8b 6c 24 ?? 56 8b 74 24 ?? 8d [0-5] 33 d2 8b c1 f7 f3 8a 44 55 00 30 04 31 41 3b cf 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DBD_2147749734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DBD!MTB"
        threat_id = "2147749734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 15 ?? ?? ?? ?? 8b c6 33 d2 f7 f3 46 8a 44 55 00 30 44 3e ff 3b 74 24 1c 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DBE_2147749735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DBE!MTB"
        threat_id = "2147749735"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 15 ?? ?? ?? ?? 33 d2 8b c6 f7 f3 8a 44 55 00 8a 14 3e 32 d0 8b 44 24 1c 88 14 3e 46 3b f0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DBF_2147749778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DBF!MTB"
        threat_id = "2147749778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff d6 8b c7 33 d2 f7 f5 8b 44 24 ?? 47 8a 0c 50 30 4c 1f ff 3b 7c 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_VDK_2147749789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.VDK!MTB"
        threat_id = "2147749789"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 44 24 18 33 d2 8d 0c 03 8b c3 f7 74 24 20 8b 44 24 14 8a 04 50 30 01}  //weight: 2, accuracy: High
        $x_2_2 = {8b c6 33 d2 f7 f3 83 c6 01 8a 44 55 00 30 44 3e ff 3b 74 24 1c 75}  //weight: 2, accuracy: High
        $x_2_3 = {0f b6 04 37 01 d8 25 ff 00 00 00 8a 04 07 8b 5c 24 20 32 04 0b 8b 74 24 1c 88 04 0e}  //weight: 2, accuracy: High
        $x_1_4 = {69 c0 fd 43 03 00 a3 ?? ?? ?? ?? 81 05 ?? ?? ?? ?? c3 9e 26 00 0f b7 05 ?? ?? ?? ?? 25 ff 7f 00 00 05 00 a1}  //weight: 1, accuracy: Low
        $x_1_5 = {30 04 1e 46 3b f7 7c 05 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_DBG_2147749865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DBG!MTB"
        threat_id = "2147749865"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff d7 33 d2 8b c6 f7 74 24 ?? 8b 44 24 ?? 8a 0c 50 30 0c 1e 46 3b f5 75}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 ff d6 33 d2 8b c7 f7 74 24 ?? 8b 44 24 ?? 8a 0c 50 30 0c 1f 47 3b fd 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DBH_2147749891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DBH!MTB"
        threat_id = "2147749891"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff d6 ?? ?? ?? ?? f7 [0-3] 8b 44 24 14 8a 0c 50 8a 14 [0-5] 32 d1 88 14 1f 47 3b ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DAU_2147749894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DAU!MTB"
        threat_id = "2147749894"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 09 81 c3 ?? ?? ?? ?? 0f b6 c9 01 f1 21 d9 8b 75 ?? 8a 0c 0e 8b 5d ?? 32 0c 3b 8b 7d ?? 8b 75 ?? 29 f7 8b 75 ?? 8b 5d ?? 88 0c 1e}  //weight: 1, accuracy: Low
        $x_1_2 = {01 f9 8b 7d ?? 21 f9 8b 7d ?? 8a 1c 0f 8b 4d ?? 8b 55 ?? 32 1c 11 8b 4d ?? 88 1c 11}  //weight: 1, accuracy: Low
        $x_1_3 = {01 da 21 f2 8a 14 17 8b 75 ?? 8b 5d ?? 32 14 1e 8b 75 ?? 88 14 1e}  //weight: 1, accuracy: Low
        $x_1_4 = {01 d1 8b 54 24 ?? 21 d1 8b 54 24 ?? 8a 0c 0a 8b 54 24 ?? 32 0c 32 8b 74 24 ?? 88 0c 1e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DBI_2147749943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DBI!MTB"
        threat_id = "2147749943"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f7 8b fa 8a 54 3c ?? 88 54 34 ?? 88 4c 3c ?? 0f b6 44 34 ?? 0f b6 c9 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 03 8a 54 14 ?? 32 c2 88 03}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 f7 33 c0 8b fa 8a 54 3c ?? 88 54 34 ?? 8b 54 24 ?? 88 5c 3c ?? 8a 44 34 ?? 81 e2 ?? ?? ?? ?? bb ?? ?? ?? ?? 03 c2 99 f7 fb 8a 19 8a 44 14 ?? 32 d8 88 19}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_HK_2147749969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.HK!wln"
        threat_id = "2147749969"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "wln: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ihavenopass" ascii //weight: 1
        $x_1_2 = "WlanGetAvailableNetworkList" ascii //weight: 1
        $x_1_3 = "/index.php" ascii //weight: 1
        $x_1_4 = "c=%s:%s" ascii //weight: 1
        $x_1_5 = {65 6e 63 72 79 70 74 69 6f 6e 3a [0-10] 4e 4f 4e 45}  //weight: 1, accuracy: Low
        $x_1_6 = "NOTE : WLAN_AVAILABLE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Emotet_HK_2147749970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.HK!svc"
        threat_id = "2147749970"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "svc: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "WinDefService" wide //weight: 1
        $x_1_2 = "c=installed" ascii //weight: 1
        $x_1_3 = "\\setup.exe" ascii //weight: 1
        $x_1_4 = {68 bb 01 00 00 68 ?? ?? ?? 00 53 ff 15 ?? ?? ?? 00 8b f0 85 f6 74}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 00 68 00 f7 04 84 6a 00 6a 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 8d 45 f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Emotet_DBJ_2147749974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DBJ!MTB"
        threat_id = "2147749974"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f7 8b fa 0f b6 54 3c ?? 88 54 34 ?? 88 4c 3c ?? 0f b6 44 34 ?? 0f b6 c9 03 c1 99 b9 ?? ?? ?? ?? f7 f9 0f b6 54 14 ?? 30 53 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DBK_2147749975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DBK!MTB"
        threat_id = "2147749975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff d3 8b c6 33 d2 f7 74 24 ?? 8b 44 24 ?? 8a 0c 50 8a 14 3e 32 d1 88 14 3e 46 3b f5 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DBL_2147750037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DBL!MTB"
        threat_id = "2147750037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f6 33 c0 8b f2 8a 54 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 81 e2 ff 00 00 00 bb ?? ?? ?? ?? 03 c2 99 f7 fb 8a 1f 8a 44 14 ?? 32 d8 88 1f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_KPV_2147750105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.KPV!MTB"
        threat_id = "2147750105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 08 8a 8c 15 ?? ?? ff ff 30 08 40 ff 4d f8 89 45 08 0f 85}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 08 32 8c 15 ?? ?? ff ff 8b 55 10 03 95 ?? ?? ff ff 88 0a 8b 85 ?? ?? ff ff 83 c0 01 89 85}  //weight: 2, accuracy: Low
        $x_2_3 = {8a 45 d0 83 65 e4 00 22 c2 08 45 cb 8a 45 ca 88 04 3e}  //weight: 2, accuracy: High
        $x_2_4 = {8b 44 24 14 83 c0 01 89 44 24 14 0f b6 54 14 18 30 50 ff 83 bc 24}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DBM_2147750123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DBM!MTB"
        threat_id = "2147750123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff d6 0f b6 44 3c ?? 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 8a 18 8a 54 14 ?? 32 da 88 18 40}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 ff d6 0f b6 44 3c ?? 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 83 c0 01 89 44 24 ?? 0f b6 54 14 ?? 30 50 ff 83 bc 24 ?? ?? ?? ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DBN_2147750124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DBN!MTB"
        threat_id = "2147750124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 99 f7 bd ?? ?? ?? ?? 0f b6 84 15 ?? ?? ?? ?? 8b 4d ?? 03 8d ?? ?? ?? ?? 0f b6 11 33 d0 8b 45 02 03 85 03 88 10 8b 8d 03 83 c1 01 89 8d 03 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_VDSK_2147750140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.VDSK!MTB"
        threat_id = "2147750140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4d cc 8a 0c 31 32 08 88 0c 33 8b 5d d0 46 3b 75 1c 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DBO_2147750191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DBO!MTB"
        threat_id = "2147750191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 15 ?? ?? ?? ?? 0f b6 44 34 ?? 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 (45|83) 8a 54 14 ?? 30 55 ff 83 bc 24 ?? ?? ?? ?? 00 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 ff 15 ?? ?? ?? ?? 0f b6 44 34 ?? 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 8a 18 8a 54 14 ?? 32 da 88 18 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DBP_2147750202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DBP!MTB"
        threat_id = "2147750202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff d6 8a 1f 8b 4c 24 ?? 8b c3 81 e1 ff 00 00 00 25 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8b 44 24 ?? 8a 08 8a 54 14 ?? 32 ca 88 08 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DBQ_2147750203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DBQ!MTB"
        threat_id = "2147750203"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff d6 0f b6 44 3c ?? 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 40 89 44 24 02 0f b6 54 14 ?? 30 50 ff 83 bc 24 ?? ?? ?? ?? 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DBR_2147750218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DBR!MTB"
        threat_id = "2147750218"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "FGDSFgsdfsgdCDDSASASS" wide //weight: 10
        $x_10_2 = "VANCYKL(" wide //weight: 10
        $x_1_3 = "CryptAcquireContextA" ascii //weight: 1
        $x_1_4 = "LoadResource" ascii //weight: 1
        $x_1_5 = "FindResourceA" ascii //weight: 1
        $x_1_6 = "LockResource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DBS_2147750254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DBS!MTB"
        threat_id = "2147750254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 07 0f b6 cb 03 c1 99 8b ce f7 f9 8b 45 8c 8a 4c 15 ?? 30 08 40 83 bd ?? ?? ?? ?? 00 89 45 8c 0f 85}  //weight: 5, accuracy: Low
        $x_2_2 = "DOKUDO" ascii //weight: 2
        $x_1_3 = "erzGGWG4tg2zyze" ascii //weight: 1
        $x_1_4 = "azga4ag3g3qg" ascii //weight: 1
        $x_1_5 = "CryptAcquireContextA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_DBT_2147750316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DBT!MTB"
        threat_id = "2147750316"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 8a 18 8a 54 14 ?? 32 da 88 18 40 89 44 24 ?? ff 4c 24 ?? 0f}  //weight: 20, accuracy: Low
        $x_20_2 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5d 00 8b 84 24 ?? ?? ?? ?? 8a 54 14 ?? 32 da 88 5d 00}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DBU_2147750319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DBU!MTB"
        threat_id = "2147750319"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0c b0 03 cb e8 ?? ?? ?? ?? 35 ?? ?? ?? ?? 3b 45 fc 74 12 8b 45 f8 46 3b 77 18 72 e3}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 e7 83 f8 ?? 72 ?? 83 f8 ?? 77 ?? 83 c0 ?? 89 45 f8 83 c6 ?? 01 55 f8 01 7d f8 29 5d f8 66 83 3e 00 0f 85 ?? ?? ?? ?? 8b 5d f4 8b 7d f0 8b 45 f8 35 ?? ?? ?? ?? 3b 45 ec 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DBV_2147750390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DBV!MTB"
        threat_id = "2147750390"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0c b0 03 cb e8 ?? ?? ?? ?? 35 ?? ?? ?? ?? 3b 45 fc 74 12 8b 45 f8 46 3b 77 18 72 e3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 16 8d 49 04 33 55 f4 8d 76 04 88 51 fc 8b c2 c1 e8 08 47 c1 ea 10 88 41 fd 88 51 fe c1 ea 08 88 51 ff 3b fb 72 d9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DBW_2147750391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DBW!MTB"
        threat_id = "2147750391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 8a 4c 14 ?? 30 08}  //weight: 3, accuracy: Low
        $x_1_2 = "&$&648tgfhjfHGDDSFDG" wide //weight: 1
        $x_1_3 = "GFDFGSdfhfgTry5678EZDDdf" wide //weight: 1
        $x_2_4 = "CryptAcquireContextA" ascii //weight: 2
        $x_1_5 = "XXADSEAFFT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_T_2147750446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.T!MTB"
        threat_id = "2147750446"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d7 33 d2 8b c6 f7 f5 8b 44 24 14 8a 0c 50 8a 14 1e 8b 44 24 1c 32 d1 88 14 1e 46 3b f0 75 ?? 5f 5d 5b 5e c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DBX_2147750545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DBX!MTB"
        threat_id = "2147750545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 45 00 8a 54 14 ?? 32 c2 88 45 00 8b 44 24 [0-5] 48 89 44 24 ?? 0f 85}  //weight: 3, accuracy: Low
        $x_1_2 = "erzGGWG4tg2zyze" ascii //weight: 1
        $x_1_3 = "azga4ag3g3qg" ascii //weight: 1
        $x_1_4 = "CryptAcquireContextA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_DBY_2147750546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DBY!MTB"
        threat_id = "2147750546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {33 d2 f7 f1 8b 44 24 ?? 8a 0c 50 8b 44 24 ?? 30 08 ff 44 24 ?? 8b 44 24 ?? 3b 44 24 ?? 0f 85}  //weight: 4, accuracy: Low
        $x_1_2 = "MqZlzg0Gugzglq0VFdK03q1fJXnWW" wide //weight: 1
        $x_1_3 = "CryptStringToBinaryA" ascii //weight: 1
        $x_1_4 = "VirtualAllocExNuma" ascii //weight: 1
        $x_1_5 = "memcpy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_DBZ_2147750547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DBZ!MTB"
        threat_id = "2147750547"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 d7 8b 75 e4 8a 3c 16 8b 55 ec 8b 75 b8 2a 1c 0e 00 fb 8b 4d ac 29 d1 8b 55 e0 8b 75 b0 88 1c 32}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 e4 b9 ?? ?? ?? ?? 8b 55 f4 8b 75 ec 8a 1c 06 29 d1 8b 55 e8 88 1c 02 01 c8 8b 4d f0 39 c8 89 45 e4 74}  //weight: 1, accuracy: Low
        $x_1_3 = "wf3t4jas2v39v23" ascii //weight: 1
        $x_1_4 = "DFG$TGY$YN" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Emotet_MX_2147750649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.MX!MTB"
        threat_id = "2147750649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 8f 02 00 00 99 f7 f9 8a 03 8a 54 14 ?? 32 c2 88 03 43 4d 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_MX_2147750649_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.MX!MTB"
        threat_id = "2147750649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 99 b9 73 0c 00 00 f7 f9 8b 45 ?? 8a 4c 15 00 30 08 40 39 9d 8c 0c 00 00 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_MX_2147750649_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.MX!MTB"
        threat_id = "2147750649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 58 10 00 00 f7 f9 8b 4c 24 ?? 8b 84 24 ?? ?? ?? ?? 8a 1c 01 8a 54 14 ?? 32 da 88 1c 01 41 3b ee 89 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_MX_2147750649_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.MX!MTB"
        threat_id = "2147750649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 99 f7 bd ?? ?? ?? ?? 0f b6 94 15 ?? ?? ?? ?? 8b 45 10 03 85 ?? ?? ?? ?? 0f b6 08 33 ca 8b 55 ?? 03 95 ?? ?? ?? ?? 88 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_MX_2147750649_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.MX!MTB"
        threat_id = "2147750649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 3b f3 7e ?? 8b 4d ?? 8d 4c 31 ?? 8a 11 88 ?? ?? ?? ?? ?? 40 49 3b c6 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {52 53 6a 01 53 50 ff 15 ?? ?? ?? ?? 85 c0 0f 95 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_MX_2147750649_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.MX!MTB"
        threat_id = "2147750649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 ff 03 00 00 f7 f9 8b 44 24 ?? 8b 4c 24 ?? 40 89 44 24 ?? 8a 54 14 ?? 30 54 01 ff 8d 4c 24 ?? c7 84 24 3c 04 00 00 ff ff ff ff e8 ?? ?? ?? ?? 39 ac 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_MX_2147750649_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.MX!MTB"
        threat_id = "2147750649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 14 08 40 89 84 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 8b c8 48 85 c9 89 84 24 ?? ?? ?? ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = "Ckw4cqK7gd6J5lv4JBZ93MPsztr0fh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_MX_2147750649_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.MX!MTB"
        threat_id = "2147750649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f9 8b 45 ?? 8a 8c 15 ?? ?? ?? ?? 30 08 40 ff 4d ?? 89 45}  //weight: 1, accuracy: Low
        $x_1_2 = "6XfuAfjKtFrW9JpX0S5C3xU4XTpblzLhEpaXW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_MX_2147750649_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.MX!MTB"
        threat_id = "2147750649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f9 8b 44 24 ?? 83 c0 01 89 44 24 ?? 8a 54 14 ?? 30 50 ff 39 ac 24 ?? ?? ?? ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = "ON5DBpnoXraRPcLfHzc2l8EBrDLvtPz4Sj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_MX_2147750649_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.MX!MTB"
        threat_id = "2147750649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f9 c1 e7 ?? 03 3d ?? ?? ?? ?? 33 f7 8d 3c 0a 33 f7 2b c6 8b f0 c1 ee ?? 03 35 ?? ?? ?? ?? 8b f8 c1 e7 ?? 03 3d ?? ?? ?? ?? 33 f7 8d 3c 02 33 f7 2b ce 81 c2 ?? ?? ?? ?? 83 6d ?? ?? 75 ?? 8b ?? ?? 5f 89 0a 89 ?? ?? 5e 8b e5 5d c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DCA_2147750672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DCA!MTB"
        threat_id = "2147750672"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 83 c0 01 83 c4 0c 89 44 24 ?? 8a 54 14 ?? 30 50 ff 83 bc 24 ?? ?? ?? ?? 00 0f 85}  //weight: 50, accuracy: Low
        $x_50_2 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 8a 18 8a 54 14 ?? 32 da 88 18}  //weight: 50, accuracy: Low
        $x_50_3 = {03 c2 83 c4 0c 99 f7 f9 8b 44 24 ?? 8a 08 8a 54 14 ?? 32 ca 88 08}  //weight: 50, accuracy: Low
        $x_20_4 = "GFDSgfsddsdSADSd" ascii //weight: 20
        $x_5_5 = "CryptAcquireContextA" ascii //weight: 5
        $x_20_6 = "GFDSGHDFHDGDFDrdfdf" ascii //weight: 20
        $x_5_7 = "MALTA" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 2 of ($x_5_*))) or
            ((1 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_DCB_2147750678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DCB!MTB"
        threat_id = "2147750678"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c8 8b c6 33 d2 f7 f1 33 c0 33 c9 8a 0c 3e 66 8b 04 53 50 51 e8 ?? ?? ?? ?? 83 c4 0c 88 04 3e 46 3b f5 75}  //weight: 5, accuracy: Low
        $x_5_2 = {0f b6 44 34 34 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 83 c4 ?? 83 c5 01 0f b6 54 14 ?? 30 55 ff 83 bc 24 ?? ?? ?? ?? 00 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DCC_2147750749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DCC!MTB"
        threat_id = "2147750749"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 c2 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 0f b6 0c 02 51 e8 ?? ?? ?? ?? 88 07 83 c4 10 (83|47) 83 6c 24 ?? 01 75}  //weight: 5, accuracy: Low
        $x_2_2 = "SERTIFICAT" ascii //weight: 2
        $x_2_3 = "Slogan" ascii //weight: 2
        $x_1_4 = "CryptAcquireContextA" ascii //weight: 1
        $x_5_5 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 0f b6 0c 33 8a d9 f6 d3 0f b6 44 14 ?? 8a d0 f6 d2 0a d3 8b 9c 24 ?? ?? ?? ?? 0a c1 22 d0 85 f6 88 14 33}  //weight: 5, accuracy: Low
        $x_5_6 = {03 c2 99 f7 fb 0f b6 04 32 8b 54 24 ?? 0f be 14 0a 8a d8 f6 d2 f6 d3 0a da 8b 54 24 ?? 0f be 14 0a 0a c2 22 d8 8b 44 24 ?? 88 19}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_DCD_2147750858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DCD!MTB"
        threat_id = "2147750858"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 d8 8b 4d d0 83 c0 01 89 0c 24 89 44 24 04 89 4d cc 89 45 c8 e8 ?? ?? ?? ?? 8b 4d e8 8b 55 cc 8a 1c 11 80 c3 ff 2a 1c 05 ?? ?? ?? ?? 8b 45 e4 88 1c 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DCE_2147750859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DCE!MTB"
        threat_id = "2147750859"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 de 21 fe 8b 7c 24 ?? 32 14 37 8b 74 24 ?? 81 c6 ?? ?? ?? ?? 8b 7c 24 ?? 88 14 0f 01 f1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DCF_2147750886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DCF!MTB"
        threat_id = "2147750886"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 99 f7 fb [0-16] ff 15 ?? ?? ?? ?? 8a 44 24 ?? 8a c8 8a d3 0a d8 8b 44 24 ?? f6 d2 f6 d1 0a d1 22 d3 88 10 [0-12] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DCG_2147750891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DCG!MTB"
        threat_id = "2147750891"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff d5 8b c6 33 d2 b9 ?? ?? ?? ?? f7 f1 8a 04 3e 8a 14 53 32 c2 88 04 3e 8b 44 24 [0-4] 3b f0 75}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 ff 15 38 c6 40 00 8b 44 24 ?? 6a ?? 33 d2 5f 8d 0c 06 8b c6 f7 f7 8b 44 24 ?? 8a 04 50 30 01 [0-3] 3b 74 24 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DCH_2147750976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DCH!MTB"
        threat_id = "2147750976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {33 d2 8a 11 03 c2 99 b9 ?? ?? ?? ?? f7 f9}  //weight: 20, accuracy: Low
        $x_20_2 = {55 8b ec 8b 45 ?? 0b 45 ?? 8b 4d ?? f7 d1 8b 55 ?? f7 d2 0b ca 23 c1}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DCI_2147750977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DCI!MTB"
        threat_id = "2147750977"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c2 d1 f8 8b c8 33 d2 8b c5 f7 f1 83 c5 01 8a 14 56 30 54 2b ff 3b 6c 24 ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 e1 c1 ea 05 6b d2 ?? 8b c1 2b c2 8a 14 18 30 14 31 41 3b cf 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DCJ_2147751121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DCJ!MTB"
        threat_id = "2147751121"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 d2 8a 11 03 c2 99 b9 ?? ?? ?? ?? f7 f9}  //weight: 5, accuracy: Low
        $x_5_2 = {8b 45 08 0b 45 0c 8b 4d 08 f7 d1 8b 55 0c f7 d2 0b ca 23 c1}  //weight: 5, accuracy: High
        $x_3_3 = "AzXdSaKvbrfghRTYh" ascii //weight: 3
        $x_4_4 = "Emotet foreve" ascii //weight: 4
        $x_3_5 = "VENESUELLA" ascii //weight: 3
        $x_5_6 = {33 d2 8a 11 b9 ?? ?? ?? ?? 03 c2 99 f7 f9}  //weight: 5, accuracy: Low
        $x_5_7 = {0f b6 17 0f b6 06 03 c2 99 b9 ?? ?? ?? ?? f7 f9 68 ?? ?? ?? ?? 68}  //weight: 5, accuracy: Low
        $x_5_8 = {8b 4c 24 04 8b 54 24 08 56 8b c1 8b f2 (0b ca f7 d0 f7 d6 0b c6 5e|f7 d0 f7 d6 0b c6 0b ca)}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_DCK_2147751122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DCK!MTB"
        threat_id = "2147751122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 50 e8 ?? ?? ?? ?? 33 d2 8b c5 b9 ?? ?? ?? ?? f7 f1 8b 44 24 ?? 8a 0c 02 8b 44 24 ?? 30 0c 28 8b 44 24}  //weight: 2, accuracy: Low
        $x_2_2 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 33 d2 8b c6 b9 ?? ?? ?? ?? f7 f1 8a 04 3e 8a 14 2a 32 c2 88 04 3e [0-3] 3b f3 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DCL_2147751123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DCL!MTB"
        threat_id = "2147751123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 6a 40 68 00 30 00 00 68 e0 07 00 00 6a 00 55 89 44 24 ?? 81 ee e0 07 00 00 ff d7 8b 4c 24 ?? 68 e0 07 00 00 03 ce 89 44 24 ?? 51 50 ff d3 83 c4 0c 6a 00 6a 40 68 00 30 00 00 56 6a 00 55 ff d7}  //weight: 2, accuracy: Low
        $x_2_2 = {56 6a 40 68 00 30 00 00 bf e0 07 00 00 57 56 ff 75 ?? 89 45 ?? 2b df ff 55 ?? 57 8b 7d ?? 8d 0c ?? 51 50 89 45 ?? ff 55 ?? 83 c4 0c 56 6a 40 68 00 30 00 00 53 56 ff 75 ?? ff 55}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DCM_2147751267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DCM!MTB"
        threat_id = "2147751267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c0 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8b 44 24 ?? 8a 4c 14 ?? 30 08 [0-3] ff 4c 24 ?? 89 44 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_VSD_2147751351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.VSD!MTB"
        threat_id = "2147751351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 08 0b 45 0c 8b 4d 08 f7 d1 8b 55 0c f7 d2 0b ca 23 c1 eb}  //weight: 2, accuracy: High
        $x_2_2 = {8b 4c 24 08 8b 54 24 0c 8b c1 8b f2 f7 d0 f7 d6 0b c6 0b ca 23 c1 5e c3}  //weight: 2, accuracy: High
        $x_2_3 = {8b 4c 24 10 8b 54 24 14 8b c1 0b 4c 24 14 f7 d0 f7 d2 0b c2 5f 5e 23 c1 5b c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DCN_2147751368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DCN!MTB"
        threat_id = "2147751368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 d2 f7 f1 8b 45 ?? 33 c9 66 8b 0c 50 51 [0-10] 50 55 8b ec 8b 45 ?? 0b 45 ?? 8b 4d ?? f7 d1 8b 55 ?? f7 d2 0b ca 23 c1 5d}  //weight: 2, accuracy: Low
        $x_1_2 = {33 c0 33 d2 8a 06 8a 17 03 c2 b9 ?? ?? ?? ?? 99 f7 f9 8b 35 ?? ?? ?? ?? 83 c4 ?? 33 c0 6a 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4c 24 04 8b 54 24 08 56 8b c1 8b f2 0b ca f7 d0 f7 d6 0b c6 5e 23 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_DCP_2147751503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DCP!MTB"
        threat_id = "2147751503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 33 d2 b9 ?? ?? ?? ?? f7 f1 8b 45 ?? 0f be 0c 10 8b 55 ?? 03 55 ?? 0f b6 02 33 c1 8b 4d ?? 03 4d ?? 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 45 fc 33 d2 b9 ?? ?? ?? ?? f7 f1 8b 45 ?? 03 45 ?? 8b 4d ?? 8a 00 32 04 11 8b 4d ?? 03 4d ?? 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_RA_2147751576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RA!MTB"
        threat_id = "2147751576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 fa 8b cf b8 04 00 00 00 03 c1 83 e8 04 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DCQ_2147751604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DCQ!MTB"
        threat_id = "2147751604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 04 29 8a 54 24 ?? 8a c8 f6 d1 f6 d2 0a d1 8a 4c 24 ?? 0a c8 8b 44 24 ?? 22 d1 88 14 28 8b 44 24 [0-4] 45 3b e8 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DCR_2147751632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DCR!MTB"
        threat_id = "2147751632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 c2 99 f7 fb 0f b6 04 32 8b 54 24 24 0f be 54 0a ff 8a d8 f6 d2 f6 d3 0a da 8b 54 24 24 0f be 54 0a ff 0a c2 22 d8 83 6c 24 10 01 88 59 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DCS_2147751644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DCS!MTB"
        threat_id = "2147751644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 33 d2 8a 07 8a 55 00 03 c2 b9 ?? ?? ?? ?? 99 f7 f9 8b 4c 24 ?? 33 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4c 24 04 8b 54 24 08 56 8b c1 8b f2 0b ca f7 d0 f7 d6 0b c6 5e 23 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DCT_2147751665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DCT!MTB"
        threat_id = "2147751665"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 15 ?? ?? ?? ?? 8b 54 24 ?? 8b 44 24 ?? 0f be 04 02 8a d0 8a cb 0a d8 8b 44 24 ?? f6 d1 f6 d2 0a ca 22 cb 88 08 [0-3] 89 44 24 ?? ff 4c 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DCU_2147751668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DCU!MTB"
        threat_id = "2147751668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 fb 8b 5d ?? 0f b6 14 13 8b 45 ?? 0f be 1c 08 89 d8 21 d0 f7 d0 09 da 21 d0 8b 5d ?? 88 04 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DCV_2147751743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DCV!MTB"
        threat_id = "2147751743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 24 0f be 04 2a 8a 54 24 18 8a c8 f6 d1 f6 d2 0a d1 8a 4c 24 ?? 0a c8 8b 44 24 ?? 22 d1 88 14 28 [0-3] 3b 6c 24 ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DCW_2147751814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DCW!MTB"
        threat_id = "2147751814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c3 99 f7 f9 [0-23] 03 c1 99 b9 [0-4] f7 f9}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4c 24 14 8b 54 24 18 8b c1 8b f2 f7 d0 f7 d6 5f 0b c6 5e 0b ca 5d 23 c1}  //weight: 1, accuracy: High
        $x_2_3 = {03 c2 99 f7 fb 0f b6 04 32 8b 54 24 ?? 0f be 54 0a ?? 8a d8 f6 d2 f6 d3 0a da 8b 54 24 ?? 0f be 54 0a ?? 0a c2 22 d8 83 6c 24 [0-2] 88 59}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_DCX_2147751917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DCX!MTB"
        threat_id = "2147751917"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 ff d6 8a 03 0f b6 4d ?? 88 45 ?? 0f b6 c0 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8b 45 f4 8a 8c 15 ?? ?? ?? ?? 30 08 [0-3] ff 4d f0 89 45 f4 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DCY_2147751918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DCY!MTB"
        threat_id = "2147751918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 8d 44 24 ?? 50 ff d3 50 ff d5 8b 4c 24 ?? 8b 54 24 ?? 8b 44 24 ?? 51 52 50 ff d7 8b 4c 24 ?? 8b 44 24 ?? 83 c4 0c 51 8b 4c 24 ?? 8d 54 24 ?? 52 50 6a 00 6a 01 6a 00 51 ff 54 24 ?? 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 68 00 10 00 00 50 57 ff 54 24 ?? 8b 4c 24 ?? 8b 54 24 ?? 51 8b f0 52 56 ff d5 8b 84 24 [0-4] 8b 54 24 ?? 83 c4 0c 50 8d 4c 24 ?? 51 56 57 6a 01 57 52 ff 54 24 ?? f7 d8 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DCZ_2147751980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DCZ!MTB"
        threat_id = "2147751980"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {6a 00 6a 40 68 00 30 00 00 68 e0 07 00 00 2d e0 07 00 00 6a 00 55 89 44 24 ?? ff d3 8b 4c 24 ?? 8b 54 24 ?? 03 d1 68 e0 07 00 00 52 50 89 44 24 2c ff d7 8b 44 24 ?? 83 c4 0c 6a 00 6a 40 68 00 30 00 00 50 6a 00 55 ff d3}  //weight: 8, accuracy: Low
        $x_1_2 = {65 47 4e 6b 5a 67 3d 00 66 67 64 62 76 74}  //weight: 1, accuracy: High
        $x_1_3 = "memcpyhIn" wide //weight: 1
        $x_1_4 = "C:\\ProgramData\\xcadzsdXzsdeSqf.dll" wide //weight: 1
        $x_1_5 = "CryptStringToBinaryAu" wide //weight: 1
        $x_1_6 = "FindResourceAX" wide //weight: 1
        $x_1_7 = "LoadResource9n" wide //weight: 1
        $x_1_8 = "CopyFileW?" wide //weight: 1
        $x_1_9 = "ShellExecuteWu" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_8_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_DDA_2147751985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DDA!MTB"
        threat_id = "2147751985"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 11 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2d 59 11 00 00 a3 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8b c0 81 c2 59 11 00 00 8b c0 a1 ?? ?? ?? ?? 8b c0 8b ca 8b c0 a3 ?? ?? ?? ?? 8b c0 31 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_KPS_2147752126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.KPS!MTB"
        threat_id = "2147752126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be 04 39 8a c8 0a d8 8b 44 24 ?? 83 c4 3c f6 d1 0a d1 22 d3 88 17}  //weight: 2, accuracy: Low
        $x_2_2 = {0f be 04 0e 8a d3 8a c8 f6 d2 0a d8 8b 44 24 ?? f6 d1 0a d1 22 d3 88 14 2e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_KMG_2147752136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.KMG!MTB"
        threat_id = "2147752136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 04 3b 88 14 3b 43 3b de 88 01 7c a6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_KMG_2147752136_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.KMG!MTB"
        threat_id = "2147752136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 c6 be 7c 0d 00 00 99 f7 fe 33 c0 8a 04 39}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_KMG_2147752136_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.KMG!MTB"
        threat_id = "2147752136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 04 3b 8a 11 83 c4 0c 88 14 3b 43 3b de 88 01 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_KMG_2147752136_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.KMG!MTB"
        threat_id = "2147752136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 04 1f 8a 0c 2b 88 0c 1f 47 81 ff c1 05 00 00 88 04 2b 0f 8c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_KMG_2147752136_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.KMG!MTB"
        threat_id = "2147752136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {99 f7 fd 33 c0 8a 04 3e 0f be 0c 0a 03 d9 b9 c3 10 00 00 03 c3 99 f7 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_KMG_2147752136_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.KMG!MTB"
        threat_id = "2147752136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 3d 27 16 00 00 7c}  //weight: 1, accuracy: High
        $x_1_2 = {8a d0 0a c1 f6 d2 0a d3 22 d0 8b 44 24 10 88 16 46 48 89 44 24 10 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_KMG_2147752136_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.KMG!MTB"
        threat_id = "2147752136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 c3 99 bb c1 05 00 00 f7 fb 0f b6 04 0f 89 7c 24 18 8a 1c 0a 88 1c 0f 88 04 0a 0f b6 04 0f 89 54 24 1c 0f b6 14 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_KMG_2147752136_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.KMG!MTB"
        threat_id = "2147752136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 08 88 0a 8b 55 08 03 55 f0 8a 45 fc 88 02 8b 4d f0 83 e9 01 89 4d f0 eb}  //weight: 1, accuracy: High
        $x_1_2 = "amuNxEcollAlautriV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_KMG_2147752136_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.KMG!MTB"
        threat_id = "2147752136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 04 1f 8a 0c 2b 88 0c 1f 47 81 ff 7c 0d 00 00 88 04 2b 0f 8c}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 04 2f 8a 14 2b 88 14 2f 83 c7 01 81 ff 7c 0d 00 00 88 04 2b 0f 8c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_KMG_2147752136_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.KMG!MTB"
        threat_id = "2147752136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 27 16 00 00 99 f7 fe 33 c0 8a ?? ?? ?? 41 81 f9 27 16 00 00 8b f2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_KMG_2147752136_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.KMG!MTB"
        threat_id = "2147752136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a d9 03 de 81 e3 ?? ?? ?? ?? 8b f3 8a 5c 34 ?? 88 5c 14 ?? 88 4c 34 ?? 0f b6 5c 14 ?? 0f b6 c9 03 d9 81 e3 ?? ?? ?? ?? 79}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_KMG_2147752136_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.KMG!MTB"
        threat_id = "2147752136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 d8 03 de 81 e3 ?? ?? ?? ?? 8b f3 8a 5c 34 ?? 88 5c 0c ?? 88 44 34 ?? 0f b6 5c 0c ?? 0f b6 c0 4d 03 d8 81 e3 ?? ?? ?? ?? 89 ac 24 ?? ?? ?? ?? 79}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_KMG_2147752136_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.KMG!MTB"
        threat_id = "2147752136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 99 f7 f9 0f b6 04 3e 6a ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a ?? 0f be 8a ?? ?? ?? ?? 03 cb 03 c1 99 b9 0f 27 00 00 f7 f9}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 04 3e 8a 14 3b 88 14 3e 83 c6 01 81 fe 0f 27 00 00 88 04 3b 0f 8c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_KMG_2147752136_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.KMG!MTB"
        threat_id = "2147752136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 8b ce f7 f9 0f b6 04 2f 8a 0c 3a 88 0c 2f 88 04 3a 0f b6 04 2f 89 54 24 1c 0f b6 14 3a}  //weight: 1, accuracy: High
        $x_1_2 = {f6 d2 f6 d1 0a d1 22 d3 88 10 40 89 44 24 ?? 8b 44 24 ?? 48 89 44 24 ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = {f6 d2 0a d8 8b 44 24 ?? f6 d1 0a d1 22 d3 88 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_KMG_2147752136_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.KMG!MTB"
        threat_id = "2147752136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a c8 88 44 24 ?? 03 cb 81 e1 ff 00 00 00 8b d9 8a 54 1c ?? 88 54 3c ?? 88 44 1c}  //weight: 1, accuracy: Low
        $x_1_2 = {8a c8 88 44 24 ?? 03 cf 81 e1 ff 00 00 00 8b f9 8a 54 3c ?? 88 54 34 ?? 88 44 3c ?? e8}  //weight: 1, accuracy: Low
        $x_1_3 = {32 c2 88 45 00 8b 44 24 ?? 45 48 89 44 24 ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_4 = {40 8a 54 04 ?? 8a 03 32 c2 88 03 43 4d 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Emotet_DDB_2147752169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DDB!MTB"
        threat_id = "2147752169"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 7d f8 8b 45 ?? 0f be 14 10 03 ca 8b c1 99 b9 ?? ?? ?? ?? f7 f9}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 8b 45 ?? 0b 45 ?? 8b 4d ?? f7 d1 8b 55 ?? f7 d2 0b ca 23 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DDC_2147752182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DDC!MTB"
        threat_id = "2147752182"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 fb 8b 6c 24 ?? 33 c0 68 ?? ?? ?? ?? 8a 04 2a 03 c1 b9 ?? ?? ?? ?? 89 54 24 ?? 8d 1c 2a 99 f7 f9 33 c0 8a 03 8b ca 89 4c 24 ?? 03 cd 8b e9 8a 55 00 88 13 88 45 00 33 c0 33 d2 8a 03 8a 11 03 c2 b9 ?? ?? ?? ?? 99 f7 f9 8b 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DDD_2147752183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DDD!MTB"
        threat_id = "2147752183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 50 e8 ?? ?? ?? ?? 8a 44 24 ?? 8a d0 8a cb f6 d2 0a c3 f6 d1 0a d1 22 d0 8b 44 24 ?? 88 10 40 83 6c 24 [0-2] 89 44 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_KSP_2147752505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.KSP!MTB"
        threat_id = "2147752505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be 04 02 8a d0 0a d8 8b 44 24 ?? f6 d1 f6 d2 0a ca 22 cb 88 08}  //weight: 2, accuracy: Low
        $x_2_2 = {0f be 04 32 8b 4c 24 20 50 51 e8 ?? ?? ?? ?? 88 06 83 c6 01 83 c4 08 83 6c 24 10 01 89 74 24 34 0f 85}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 54 24 24 0f be 04 16 50 55 e8 ?? ?? ?? ?? 88 04 1e 83 c6 01 83 c4 08 3b 74 24 2c 0f 82}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DDG_2147752562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DDG!MTB"
        threat_id = "2147752562"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {6a 40 68 00 30 00 00 56 57 ff 54 24 ?? 50 ff 54 24 ?? 8b 54 24 ?? 8b f0 8b 44 24 ?? 52 50 56 e8 ?? ?? ?? ?? 83 c4 0c ff d6 5f 5e b8 01 00 00 00 5b 83 c4 20}  //weight: 8, accuracy: Low
        $x_4_2 = "2YPZhNmF2Kkg2KrYsdit2YrY=" ascii //weight: 4
        $x_1_3 = "GetCurrentProcess" wide //weight: 1
        $x_1_4 = "VirtualAllocExNuma" wide //weight: 1
        $x_1_5 = "CryptStringToBinaryA" wide //weight: 1
        $x_1_6 = "FindResourceA" wide //weight: 1
        $x_1_7 = "LoadResource" wide //weight: 1
        $x_1_8 = "SizeofResource" wide //weight: 1
        $x_1_9 = "LockResource" wide //weight: 1
        $x_1_10 = "Please enter a currency." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_8_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_DDH_2147752667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DDH!MTB"
        threat_id = "2147752667"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d0 89 4c 24 ?? 0a 44 24 ?? f6 d2 f6 d1 0a d1 22 d0 8b 44 24 ?? 88 10}  //weight: 1, accuracy: Low
        $x_1_2 = "2YPZhNmF2Kkg2KrYsdit2YrY=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DDI_2147752700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DDI!MTB"
        threat_id = "2147752700"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 f9 8b 4d ?? 0f b6 04 32 8b 55 ?? 8a d8 f6 d3 0f be 14 0a 89 55 ?? 0a 45 ?? f6 d2 0a da 22 d8 88 19}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_ID_2147752743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.ID!MTB"
        threat_id = "2147752743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5e 5b 5d c3 8b 44 24 ?? 8b 4c 24 ?? 81 f1 ?? ?? ?? ?? 8b 54 24 ?? 8a 1c 02 8b 74 24 ?? 88 1c 06 01 c8 8b 4c 24 ?? 39 c8 89 44 24 ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DDJ_2147752779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DDJ!MTB"
        threat_id = "2147752779"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d0 89 4c 24 ?? f6 d2 f6 d1 0a d1 8a 4c 24 00 0a c1 22 d0 8b 44 24 ?? 88 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DSP_2147752814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DSP!MTB"
        threat_id = "2147752814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 44 24 1c 8a d0 8a d9 f6 d2 f6 d3 0a d3 0a c1 22 d0 88 16}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DVP_2147752817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DVP!MTB"
        threat_id = "2147752817"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c7 c1 e9 05 03 0d ?? ?? ?? ?? c1 e0 04 03 05 ?? ?? ?? ?? 33 c8 8d 04 3b 33 c8 8d 9b ?? ?? ?? ?? 2b f1 4a 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DDK_2147752835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DDK!MTB"
        threat_id = "2147752835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 50 e8 ?? ?? ?? ?? 8a 44 24 20 8a 4c 24 14 8a d0 0a 44 24 14 f6 d2 f6 d1 0a d1 22 d0 8b 44 24 34 88 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DDL_2147752890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DDL!MTB"
        threat_id = "2147752890"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a c8 8a d3 0a d8 8b 44 24 24 f6 d2 f6 d1 0a d1 22 d3 88 14 07}  //weight: 1, accuracy: High
        $x_1_2 = {03 c3 99 bb 7c 0d 00 00 f7 fb [0-27] 03 c2 99 8b f3 f7 fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DDM_2147753000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DDM!MTB"
        threat_id = "2147753000"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 04 8b 54 24 08 56 8b c1 8b f2 0b ca f7 d0 f7 d6 0b c6 5e 23 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_TA_2147753045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.TA!MSR"
        threat_id = "2147753045"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "28C4C820-401A-101B-A3C9-08002B2F49FB" wide //weight: 1
        $x_1_2 = "Burnamedoxi" ascii //weight: 1
        $x_1_3 = "MethCallEngine" wide //weight: 1
        $x_1_4 = "\\Vertopesto\\BHerolIfop.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DDN_2147753056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DDN!MTB"
        threat_id = "2147753056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d0 f6 d2 f6 d3 0a da 8a 54 24 ?? 0a d0 8b 44 24 ?? 22 da 88 1c 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_KSV_2147753175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.KSV!MTB"
        threat_id = "2147753175"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a d0 8a d9 0a c1 8b 4c 24 ?? f6 d2 f6 d3 0a d3 22 d0 8b 44 24 ?? 88 14 08 04 00 8a 4c 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PKV_2147753184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PKV!MTB"
        threat_id = "2147753184"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 04 37 03 c1 99 b9 c3 10 00 00 f7 f9 0f b6 04 32 8b 54 24 10 0f be 0c 2a 51 50 e8 ?? ?? ?? ?? 88 45 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DDO_2147753195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DDO!MTB"
        threat_id = "2147753195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a cb 8a c2 f6 d1 f6 d0 0a da 0a c8 be ?? ?? ?? ?? 8b 45 ?? 22 cb 8b 5d ?? 88 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DDR_2147753196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DDR!MTB"
        threat_id = "2147753196"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 08 8b 54 24 0c 8b c1 f7 d0 8b f2 f7 d6 0b c6 0b ca 23 c1 5e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DPS_2147753265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DPS!MTB"
        threat_id = "2147753265"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4c 24 10 0f be 04 01 50 ff 74 24 ?? e8 ?? ?? ?? ?? 8b 54 24 ?? 59 59 8b 4c 24 10 88 04 11 04 00 8b 44 24}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 6c 24 14 8b 4c 24 ?? 8b 44 24 1c 0f be 14 29 52 50 e8 ?? ?? ?? ?? 8b 4c 24 ?? 83 c4 08 88 04 29}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_NB_2147753384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.NB!MTB"
        threat_id = "2147753384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 03 2b 06 35 ff ff ff ff 03 06 89 02 2b 35 ?? ?? ?? ?? 47 8b c7 ff 75 18 8f 45 f4 2b 45 f4}  //weight: 10, accuracy: Low
        $x_3_2 = "kbdgr.dll" ascii //weight: 3
        $x_3_3 = "KbdLayerDescriptor" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_NB_2147753384_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.NB!MTB"
        threat_id = "2147753384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b c7 0f af c7 89 44 24 10 8d 54 2d 00 2b c2 89 54 24 24 8d 14 41 a1 60 11 0d 10 8d 48 02 0f af c8 2b d1 03 54 24 10 8d 04 5b 03 c0 b9 06 00 00 00 2b c8 0f af cb 8d}  //weight: 10, accuracy: High
        $x_3_2 = "EmotionSelDemo" ascii //weight: 3
        $x_3_3 = "hoodlum1980" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_NM_2147753391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.NM!MTB"
        threat_id = "2147753391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5d 00 8b 44 24 30 83 c4 20 8a 54 14 14 32 da 88 5d 00 45 48 89 44 24 10 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DDP_2147753417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DDP!MTB"
        threat_id = "2147753417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 55 ?? 56 6a 00 89 45 ?? ff 55 ?? 8b 55 ?? 52 89 45 ?? ff 55 ?? 8b 4d ?? 6a 00 89 45 ?? 8b 85 ?? ?? ?? ?? 50 68 00 30 00 00 51 6a 00 ff d3 50 ff d7}  //weight: 1, accuracy: Low
        $x_1_2 = {bf 00 30 00 00 50 57 ff 75 d8 53 ff 55 bc 50 ff 55 b8 ff 75 d8 89 45 dc ff 75 c4 50 e8 80 53 00 00 83 c4 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DDQ_2147753464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DDQ!MTB"
        threat_id = "2147753464"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 57 8d 4c 24 1c 51 57 6a 01 50 56 ff d5 85 c0 74 [0-7] e8 ?? ?? ?? ?? 8b 54 24 14 83 c4 04 57 57 8d 4c 24 1c 51 50 6a 01 52 56 89 44 24 54 ff d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DDS_2147753544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DDS!MTB"
        threat_id = "2147753544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 6a 40 68 00 30 00 00 56 57 8b d8 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b f8 56 53 57 e8 ?? ?? ?? ?? 8b 44 24 1c 83 c4 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {bf 00 30 00 00 50 57 ff 75 d8 53 ff 55 c0 50 ff 55 c4 ff 75 d8 89 45 dc ff 75 bc 50 e8 ?? ?? ?? ?? 83 c4 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_MR_2147753785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.MR!MTB"
        threat_id = "2147753785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d7 8b ca 8b c1 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11 5f 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_U_2147753789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.U!MTB"
        threat_id = "2147753789"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 40 68 00 30 00 00 56 6a 00 8b d8 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 56 8b f8 53 57 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 24 8b 08 8b 54 24 20 51 50 8b 44 24 18 52 53 6a 01 53 50 ff 15 ?? ?? ?? 00 5f 85 c0 5b 0f 95 c0 5e 83 c4 08 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DDT_2147753834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DDT!MTB"
        threat_id = "2147753834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 30 00 00 50 53 ff 15 ?? ?? ?? ?? 50 ff d5 8b 4c 24 ?? 8b 54 24 ?? 51 8b f0 52 56 e8 ?? ?? ?? ?? 8b 44 24 ?? 8b 4c 24 ?? 83 c4 0c 53 50 68 00 30 00 00 51 53 ff 15 ?? ?? ?? ?? 50 ff d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DDU_2147753835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DDU!MTB"
        threat_id = "2147753835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c8 31 f6 89 55 cc 89 f2 8b 75 cc f7 f6 89 cf 83 e7 03 8b 5d e8 8a 1c 0b 8b 75 d0 83 fe 02 0f 47 fa 2a 1c 3d ?? ?? ?? ?? 01 ce 8b 55 e4 88 1c 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DDV_2147753836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DDV!MTB"
        threat_id = "2147753836"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "amuNxEcollAlautriV" ascii //weight: 1
        $x_1_2 = "3NJ72hlhWvf7769Rmdnt9Z6DVO" ascii //weight: 1
        $x_1_3 = "OmiHLHtNA9hWFro" ascii //weight: 1
        $x_1_4 = "FDCczcxxxGGH873495748tghjhfj" ascii //weight: 1
        $x_1_5 = "QQyvgS5PP4uaEnL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Emotet_DDW_2147754025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DDW!MTB"
        threat_id = "2147754025"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d7 85 c0 75 26 6a 08 6a 01 53 53 8d 54 24 ?? 52 ff d7 85 c0 75 15 6a 08 6a 01 53 53 8d 44 24 00 50 ff d7}  //weight: 1, accuracy: Low
        $x_1_2 = {85 c0 75 2e 6a 08 6a 01 53 53 8d 4c 24 ?? 51 ff 15 ?? ?? ?? ?? 85 c0 75 19 6a 08 6a 01 53 53 8d 54 24 00 52 ff 15 ?? ?? ?? ?? 85 c0 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DDX_2147754097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DDX!MTB"
        threat_id = "2147754097"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 75 33 6a 08 6a 01 6a 00 6a 00 8d 4d ?? 51 ff 15 ?? ?? ?? ?? 85 c0 75 1d 6a 08 6a 01 6a 00 6a 00 8d 55 00 52 ff 15 01 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DDY_2147754102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DDY!MTB"
        threat_id = "2147754102"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 08 6a 01 53 53 8d [0-3] 51 ff 15 ?? ?? ?? ?? 85 c0 75 ?? 6a 08 6a 01 53 53 8d [0-3] 52 ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 8b [0-3] 8d [0-3] 50 53 53 68 34 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RGM_2147754146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RGM!MTB"
        threat_id = "2147754146"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f1 8b 45 ?? 0f be 0c 10 8b 55 ?? 0f b6 84 15 ?? ?? ?? ?? 33 c1 8b 4d ?? 88 84 0d ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DDZ_2147754157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DDZ!MTB"
        threat_id = "2147754157"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e3 ff 00 00 00 03 c3 25 ?? ?? ?? ?? 8a 44 04 ?? 8a 1e 32 d8 88 1e 46 4f 75}  //weight: 1, accuracy: Low
        $x_1_2 = {03 ca 83 c4 ?? 81 e1 ?? ?? ?? ?? 8a 55 00 8a 44 0c ?? 32 d0 8b 44 24 ?? 88 55 00 45 48 89 44 24 ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = {03 d8 81 e3 ?? ?? ?? ?? 89 ac 24 ?? ?? ?? ?? 0f b6 44 1c ?? 30 07 83 c7 01 85 ed 75}  //weight: 1, accuracy: Low
        $x_1_4 = "5aBhPnlAnzPfEe3LfsVqgI82Te" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DEA_2147754214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DEA!MTB"
        threat_id = "2147754214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 ca 81 e1 ?? ?? ?? ?? 8b 44 24 ?? 8a 10 8a 4c 0c ?? 32 d1 88 10 [0-4] 89 44 24 ?? ff 4c 24 ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = "6GRVuKdQWOgqZYvQBHioU9847" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_RDP_2147754223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RDP!MTB"
        threat_id = "2147754223"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c9 00 ff ff ff 41 8b 44 24 ?? 8a 4c 0c ?? 8a 10 32 d1 88 10 40 89 44 24 ?? 8b 44 24 ?? 48 89 44 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DEB_2147754254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DEB!MTB"
        threat_id = "2147754254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5d 00 8b 44 24 ?? 8a 54 14 ?? 32 da 88 5d 00 45 48 89 44 24 ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 06 0f b6 cb 03 c1 8b cf 99 f7 f9 8b 45 14 8a 8c 15 ?? ?? ?? ?? 30 08 40 ff 4d 0c 89 45 14 75}  //weight: 1, accuracy: Low
        $x_1_3 = "nD9nR3RLhInjVc7TVdTYU98qoXe7Pps" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_RDS_2147754260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RDS!MTB"
        threat_id = "2147754260"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c9 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8b 45 ?? 8a 8c 15 ?? ?? ?? ?? 30 08 40 ff 4d ?? 89 45 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GKM_2147754306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GKM!MTB"
        threat_id = "2147754306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 99 8b f1 f7 fe 8b 45 ?? 8a ?? 15 [0-4] 30 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GKM_2147754306_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GKM!MTB"
        threat_id = "2147754306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 c1 b9 64 01 00 00 99 f7 f9 8a 03 8a 54 14 ?? 32 c2 88 03 43 4d 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GKM_2147754306_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GKM!MTB"
        threat_id = "2147754306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 5c af 00 00 f7 f9 8a 5d 00 8d 4c 24 ?? 8a 94 14 ?? ?? ?? ?? 32 da 88 5d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GKM_2147754306_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GKM!MTB"
        threat_id = "2147754306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 99 b9 6b 1c 00 00 f7 f9 45 8a 54 14 ?? 30 55 ?? 83 bc 24 ?? ?? ?? ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GKM_2147754306_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GKM!MTB"
        threat_id = "2147754306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c9 03 c1 99 b9 21 d8 00 00 f7 f9 8a 45 00 8d 4c 24 ?? 8a 9c 14 ?? ?? ?? ?? 32 d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GKM_2147754306_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GKM!MTB"
        threat_id = "2147754306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce 99 f7 f9 8b 45 ?? 83 c4 18 8a 8c 15 ?? ?? ?? ?? 30 08 40 ff 4d ?? 89 45 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GKM_2147754306_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GKM!MTB"
        threat_id = "2147754306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {99 b9 e5 08 00 00 f7 f9 8b 4c 24 ?? 8b 84 24 ?? ?? ?? ?? 8a 1c 01 8a 54 14 ?? 32 da 88 1c 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GKM_2147754306_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GKM!MTB"
        threat_id = "2147754306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 96 16 00 00 f7 f9 8b 44 24 ?? 83 c0 01 8b ce 89 44 24 ?? 0f b6 94 14 ?? ?? ?? ?? 30 50 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GKM_2147754306_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GKM!MTB"
        threat_id = "2147754306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 cb 03 c1 99 8b ce f7 f9 8b 45 ?? 8a 4c 15 00 30 08 40 83 bd ?? ?? ?? ?? 00 89 45 ?? 0f 85}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GKM_2147754306_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GKM!MTB"
        threat_id = "2147754306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {99 b9 72 1b 00 00 f7 f9 8a 5d 00 8b 44 24 ?? 8a 54 14 ?? 32 da 88 5d 00 45 48 89 44 24 ?? 0f 85}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GKM_2147754306_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GKM!MTB"
        threat_id = "2147754306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 f9 8b 44 24 ?? 8a 08 8a 54 14 ?? 32 ca 88 08 40 89 44 24 ?? 8b 44 24 ?? 48 89 44 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GKM_2147754306_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GKM!MTB"
        threat_id = "2147754306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 8b ce f7 f9 8b 45 ?? 83 4d ?? ?? 8a 8c 15 ?? ?? ?? ?? 30 08 40 8d 8d ?? ?? ?? ?? 89 45 ?? e8 ?? ?? ?? ?? ff 4d ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GKM_2147754306_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GKM!MTB"
        threat_id = "2147754306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {99 f7 f9 8b 44 24 ?? 8b 8c 24 ?? ?? ?? ?? 8a 54 14 ?? 30 14 08 40 89 44 24 ?? 8b 84 24 ?? ?? ?? ?? 8b c8 48 85 c9 89 84 24 ?? ?? ?? ?? 0f 85}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GKM_2147754306_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GKM!MTB"
        threat_id = "2147754306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 99 b9 20 04 00 00 f7 f9 8a 5d 00 8b 44 24 ?? 8a 54 14 ?? 32 da 88 5d 00}  //weight: 1, accuracy: Low
        $x_1_2 = {03 c1 99 b9 20 04 00 00 f7 f9 45 0f b6 54 14 ?? 30 55 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_GKM_2147754306_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GKM!MTB"
        threat_id = "2147754306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {99 f7 f9 8b 84 24 ?? ?? ?? ?? 8a 08 8a 94 14 ?? ?? ?? ?? 32 ca 88 08 40 89 84 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 48 89 84 24 ?? ?? ?? ?? 0f 85}  //weight: 2, accuracy: Low
        $x_2_2 = {b9 28 11 00 00 99 f7 f9 8a 5d 00 8b 44 24 ?? 8a 54 14 ?? 32 da 88 5d 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_GKM_2147754306_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GKM!MTB"
        threat_id = "2147754306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 be 33 06 01 00 f7 f6 41 81 f9 33 06 01 00 8b f2 8a 44 34 ?? 88 44 0c ?? 88 5c 34 ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 be 53 88 00 00 f7 f6 41 81 f9 53 88 00 00 8b f2 8a 44 34 ?? 88 44 0c ?? 88 5c 34 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DEC_2147754342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DEC!MTB"
        threat_id = "2147754342"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 99 b9 ?? ?? ?? ?? f7 f9 8a 04 2b 8a 54 14 ?? 32 c2 88 04 2b 8b 84 24 [0-9] 85 c0 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = "A0kBtBJOLnYX5IlkVFhbHFt0rWDyMhCEBmkG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_MXI_2147754355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.MXI!MTB"
        threat_id = "2147754355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 89 d8 ba 00 00 00 00 f7 f1 8a 44 15 00 30 04 1e 43 39 5c 24}  //weight: 1, accuracy: High
        $x_1_2 = "F$qp818J9sDvbcVAac" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DED_2147754407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DED!MTB"
        threat_id = "2147754407"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 03 8a 54 14 ?? 32 c2 88 03 43 4d 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = "bhmWcrq303rIEQO70TYyjadVpnYP0X50B" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DEE_2147754416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DEE!MTB"
        threat_id = "2147754416"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 99 b9 ?? ?? ?? ?? f7 f9 8b 4c 24 ?? 8b 84 24 ?? ?? ?? ?? 8a 1c 01 8a 54 14 ?? 32 da 88 1c 01 [0-4] 89 4c 24 ?? 8b 8c 24 ?? ?? ?? ?? 85 c9 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = "m6sCeEmOWl361fw9QXDPteV1Z5jw19Wojb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DEF_2147754459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DEF!MTB"
        threat_id = "2147754459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 81 e2 ff 00 00 00 8a 44 0c ?? b9 ?? ?? ?? ?? 03 c2 8b ac 24 ?? ?? ?? ?? 99 f7 f9 8b 4c 24 ?? 8a 04 29 8a 54 14 ?? 32 c2 88 04 29}  //weight: 1, accuracy: Low
        $x_1_2 = "2enNYJDnJqP2uf6PBgryoOV3tiGzagBO7F" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DEG_2147754460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DEG!MTB"
        threat_id = "2147754460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 18 8b 4c 24 24 40 89 44 24 18 8a 54 14 28 30 54 01 ff}  //weight: 1, accuracy: Low
        $x_1_2 = "pr8vhOwZa7Ht4FKf99j9XtopZZOOv" ascii //weight: 1
        $x_1_3 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 4c 24 14 8b 44 24 18 83 c1 01 89 4c 24 14 8a 54 14 24 30 54 08 ff}  //weight: 1, accuracy: Low
        $x_1_4 = "9jk5YPrR0uoqvOqG5Sznz2VqwMkTfAd4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PVE_2147754466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PVE!MTB"
        threat_id = "2147754466"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b9 7d 03 00 00 f7 f9 8b 44 24 18 8b 4c 24 24 40 89 44 24 18 8a 54 14 28 30 54 01 ff 83 bc 24 ?? ?? ?? ?? 00 0f 85}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DEH_2147754538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DEH!MTB"
        threat_id = "2147754538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 81 e1 ff 00 00 00 8a 44 14 ?? 8b ac 24 ?? ?? ?? ?? 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8b 44 24 ?? c7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 8a 0c 28 8a 54 14 ?? 32 ca 88 0c 28}  //weight: 1, accuracy: Low
        $x_1_2 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 8b 8c 24 ?? ?? ?? ?? 8a 54 14 ?? 30 14 08 40 89 44 24 ?? 8b 84 24 ?? ?? ?? ?? 85 c0 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = {03 c1 99 b9 a1 02 00 00 f7 f9 8b 44 24 ?? 8b 4c 24 ?? 83 c0 01 89 44 24 ?? 8a 54 14 ?? 30 54 01 ff}  //weight: 1, accuracy: Low
        $x_1_4 = "qxZm0g7DZEubi8dNqtlY8xcWLd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_OP_2147754556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.OP!MTB"
        threat_id = "2147754556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 44 04 24 0f b6 4c 24 17 03 c1 99 b9 a1 02 00 00 f7 f9 8b 44 24 20 8b 8c 24 d4 02 00 00 8a 54 14 24 30 14 08 40 89 44 24 20 8b 84 24 d8 02 00 00 85 c0 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DEI_2147754568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DEI!MTB"
        threat_id = "2147754568"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 20 8b 4c 24 28 (40|83) 89 44 24 20 8a 54 14 30 30 54 01 ff}  //weight: 2, accuracy: Low
        $x_2_2 = "KWoAbHsCT4qk5XhfeHpqAw4Cm8Ey7yy4vAKtx4nZnP7Cl" ascii //weight: 2
        $x_1_3 = "hgcfsghdfasghd" wide //weight: 1
        $x_1_4 = "hgdghdhgdhgdhgd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_PVM_2147754702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PVM!MTB"
        threat_id = "2147754702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b9 7c 03 00 00 f7 f9 8a 5d 00 8b 44 24 14 83 c0 f0 c7 84 24 ?? ?? ?? ?? ff ff ff ff 8d 48 0c 8a 54 14 18 32 da 88 5d 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DEJ_2147754725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DEJ!MTB"
        threat_id = "2147754725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 14 (45|83) 83 c5 01 c7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 8d 48 0c 8a 54 14 1c 30 55 ff}  //weight: 1, accuracy: Low
        $x_1_2 = "nffkDLfoEWDmR3FCafhArfgdjy6ktgHOMAW" ascii //weight: 1
        $x_1_3 = "Qdzt8LmIPQpmswdALdPLNFQeJODptY6CMZL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PVF_2147754782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PVF!MTB"
        threat_id = "2147754782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 94 15 ?? ?? ff ff 8b 45 10 03 85 ?? ?? ff ff 0f b6 08 33 ca 8b 55 10 03 95 ?? ?? ff ff 88 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PVG_2147754783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PVG!MTB"
        threat_id = "2147754783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 44 34 1c 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 83 c5 01 8a 54 14 1c 30 55 ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PVI_2147754785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PVI!MTB"
        threat_id = "2147754785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 c3 03 c1 99 b9 98 04 00 00 f7 f9 8b 85 ?? ?? ff ff 8d 76 01 8a 8c 15 ?? ?? ff ff 30 4e ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DEK_2147754789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DEK!MTB"
        threat_id = "2147754789"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 03 8d 4c 24 ?? c7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 8a 54 14 ?? 32 c2 88 03}  //weight: 1, accuracy: Low
        $x_1_2 = "QA0jXQRlCPwJmmbtbE3dSKDEX2gYOZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DEL_2147754792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DEL!MTB"
        threat_id = "2147754792"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 8b ce 99 f7 f9 8b 45 14 83 4d fc ff 8a 8c 15 ?? ?? ?? ?? 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = "2q6wcm0g1om3lEMShyJ8mCzMpMfWjd8B" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PVJ_2147754840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PVJ!MTB"
        threat_id = "2147754840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 5d 00 8b 44 24 10 83 c0 f0 c7 84 24 ?? ?? ?? ?? ff ff ff ff 8d 48 0c 8a 54 14 14 32 da 88 5d 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PVL_2147754885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PVL!MTB"
        threat_id = "2147754885"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 4d f3 03 c1 99 b9 7d 1a 00 00 f7 f9 8b 45 e8 8a 4c 15 00 30 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DEM_2147754907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DEM!MTB"
        threat_id = "2147754907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 dc 2b c8 8b 55 e0 2b ca 8b 45 e4 2b c8 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 8b 55 0c 8b 45 e8 88 04 0a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DEM_2147754907_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DEM!MTB"
        threat_id = "2147754907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 d3 03 c2 99 b9 ?? ?? ?? ?? f7 f9 8b 4c 24 1c 8b 44 24 24 41 89 4c 24 1c 8a 54 14 28 30 54 01 ff}  //weight: 1, accuracy: Low
        $x_1_2 = "ujtjKDOd7BAwBfMb311cVqCwcI6eJvnjaA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_SK_2147754915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SK!MTB"
        threat_id = "2147754915"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "O#ww#P#######wO" ascii //weight: 1
        $x_1_2 = "YUQ9F*miOq" ascii //weight: 1
        $x_1_3 = "6!h@J0Vi#O" ascii //weight: 1
        $x_1_4 = "ni7=8hLO6o" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_SK_2147754915_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SK!MTB"
        threat_id = "2147754915"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 00 8b 55 ?? 3b 15 ?? ?? ?? ?? 72 02 eb 42 8b 45 ?? 89 45 ?? c7 45 ?? ?? ?? ?? ?? 8b 4d ?? 03 4d ?? c6 01 00 c7 45 ?? 00 00 00 00 8b 55 ?? 03 55 ?? 8b 45 ?? 03 45 ?? 8a 08 88 0a c7 45 ?? ?? ?? ?? ?? 8b 55 ?? 83 c2 01 89 55 ?? e9 ?? ff ff ff 8b e5 5d c3}  //weight: 2, accuracy: Low
        $x_2_2 = {55 8b ec 81 ec b0 00 00 00 c7 45 ?? 40 00 00 00 c7 45 ?? 00 00 00 00 a1 ?? ?? ?? ?? 89 45 ?? c7 45 ?? ff ff ff ff c6 45 ?? 0d 8b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? ff 75 ?? 68 00 30 00 00 8b 45 ?? 50 ff 75 ?? ff 35 ?? ?? ?? ?? 59 a1 ?? ?? ?? ?? ff d0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DEN_2147754968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DEN!MTB"
        threat_id = "2147754968"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 03 8a 54 14 1c 32 c2 88 03}  //weight: 1, accuracy: Low
        $x_1_2 = "50gTGs4plLI4DfE4lOnCYXve9mSZZ9eWJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DEO_2147754986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DEO!MTB"
        threat_id = "2147754986"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 81 e2 ff 00 00 00 8a 84 0c ?? ?? ?? ?? b9 3d 23 00 00 03 c2 99 f7 f9 8b 84 24 ?? ?? ?? ?? 8b 8c 24 ?? ?? ?? ?? 8a 94 14 00 30 14 08}  //weight: 1, accuracy: Low
        $x_1_2 = "g7hv3Mg9p3bLWDahvJPWtaBIwwWyQjR2ylJymLW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DEP_2147755070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DEP!MTB"
        threat_id = "2147755070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 99 b9 ab 0a 00 00 f7 f9 8b 8c 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 83 c1 01 89 8c 24 00 8a 94 14 ?? ?? ?? ?? 30 54 08 ff}  //weight: 1, accuracy: Low
        $x_1_2 = "U7vNOvsxPS4CQd5cYIMc7S7ik9wUgx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PVN_2147755270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PVN!MTB"
        threat_id = "2147755270"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 4d f3 03 c1 99 f7 fb 8b 45 e8 8a 4c 15 00 30 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PVH_2147755277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PVH!MTB"
        threat_id = "2147755277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 07 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 54 83 c4 38 8a 4c 14 24 30 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DEQ_2147755295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DEQ!MTB"
        threat_id = "2147755295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 b9 55 02 00 00 f7 f9 83 c4 38 45 0f b6 54 14 18 30 55 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PVO_2147755329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PVO!MTB"
        threat_id = "2147755329"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xEl5fRAyVuLFbO3gJ07XnIn2kGnvYh33i6" ascii //weight: 1
        $x_1_2 = "AZjJqR8rwihiivi6siMWJBOLNt6EeQnKQSrtmJP2L2LZ4pWLcaSfgpMLD9hGEPby" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PVP_2147755330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PVP!MTB"
        threat_id = "2147755330"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 54 24 1b 03 c2 99 b9 73 08 00 00 f7 f9 8b 84 24 ?? ?? ?? ?? 83 c0 01 89 84 24 ?? ?? ?? ?? 8a 94 14 ?? ?? ?? ?? 30 54 03 ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DER_2147755355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DER!MTB"
        threat_id = "2147755355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 6c 24 44 8b c7 2b c1 2b c6 03 54 24 40 8d 04 82 8b 54 24 4c 03 c3 8a 04 10 30 45}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DER_2147755355_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DER!MTB"
        threat_id = "2147755355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 99 b9 e5 08 00 00 f7 f9 8b 4c 24 ?? 8b 84 24 ?? ?? ?? ?? 8a 54 14 ?? 30 14 01}  //weight: 1, accuracy: Low
        $x_1_2 = "PAypbMJhqHT27rrPVUHVkuLzxcR2hHHzdnt4XJpWEH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DES_2147755356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DES!MTB"
        threat_id = "2147755356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 01 6a 00 6a 00 8d 45 ?? 50 ff 55 ?? 85 c0 75 ?? 6a 08 6a 01 6a 00 6a 00 8d 4d 00 51 ff 55 01 85 c0 75 ?? 68 00 00 00 f0 6a 01 6a 00 6a 00 8d 55 00 52 ff 55}  //weight: 1, accuracy: Low
        $x_1_2 = "rcOOobhKjnRKfBtDJxBSTroidU" wide //weight: 1
        $x_1_3 = "9Ml3cd{pH#e|9z3Y@k{GnWcnlJqyJqIyrZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PVQ_2147755416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PVQ!MTB"
        threat_id = "2147755416"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 4c 24 17 03 c1 99 b9 df 08 00 00 f7 f9 8b 4c 24 20 8b 84 24 ?? ?? ?? ?? 8a 54 14 24 30 14 01}  //weight: 1, accuracy: Low
        $x_1_2 = "mf5Djj4cbIylqdQwZNwnH8wCZF3uv424zyd6yeg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DET_2147755457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DET!MTB"
        threat_id = "2147755457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 4d f3 0f b6 07 03 c1 99 8b ce f7 f9 8b 45 e8 8a 4c 15 00 30 08 [0-3] 83 bd ?? ?? ?? ?? 00 89 45 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "z9WhHmpuhMXgxgcbFIbMxZD6zxWuyZl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PVT_2147755480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PVT!MTB"
        threat_id = "2147755480"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 04 30 88 cc 0f b6 cc 66 c7 84 24 86 00 00 00 00 00 8b 54 24 34 8a 24 0a 30 c4 c6 44 24 73 56 8b 4c 24 24 88 24 31}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PVU_2147755481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PVU!MTB"
        threat_id = "2147755481"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 1c 0a 8b 4c 24 18 32 1c 31 c6 44 24 47 1e 8b 74 24 3c 8a 7c 24 47 8b 4c 24 14 88 1c 31}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DEU_2147755506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DEU!MTB"
        threat_id = "2147755506"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 99 b9 4f 11 00 00 f7 f9 8b 85 ?? ?? ?? ?? 8a 8c 15 ?? ?? ?? ?? 30 08 [0-4] ff 8d ?? ?? ?? ?? 89 85 00 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = "ctlcyoKQWaJggabAeKrLNftYqRD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PVV_2147755542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PVV!MTB"
        threat_id = "2147755542"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c9 03 c1 99 b9 05 17 00 00 f7 f9 0f b6 94 15 ?? ?? ?? ?? 30 53 ff 1e 00 0f b6 94 3d ?? ?? ?? ?? 88 94 35 ?? ?? ?? ?? 88 8c 3d ?? ?? ?? ?? 0f b6 84 35}  //weight: 1, accuracy: Low
        $x_1_2 = "cloWCQbdCJl8US4VDdLQ4Swyicc9As5b41Ma6MOHdBO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DEV_2147755581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DEV!MTB"
        threat_id = "2147755581"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 99 b9 ca 0c 00 00 f7 f9 8b 4c 24 18 8b ac 24 ?? ?? ?? ?? 8a 04 29 8a 54 14 20 32 c2 88 04 29}  //weight: 1, accuracy: Low
        $x_1_2 = "NzKyf3NyHWlewCVXSopL3mSPJC4QZNv3JsDW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DEW_2147755582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DEW!MTB"
        threat_id = "2147755582"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 0f b6 4d 0f 89 45 f0 8b 45 ec 0f b6 84 05 ?? ?? ?? ?? 03 c1 8b cb 99 f7 f9 8b 45 f0 8a 8c 15 00 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 81 e1 ff 00 00 00 8a 84 14 ?? ?? ?? ?? 03 c1 b9 cf 08 00 00 99 f7 f9 8b 84 24 ?? ?? ?? ?? 8b 8c 24 ?? ?? ?? ?? 8a 94 14 00 30 14 08}  //weight: 1, accuracy: Low
        $x_1_3 = "SWFtCmwxRvOqQHPCyIc3d5KR6pV93TGkRaX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DEX_2147755587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DEX!MTB"
        threat_id = "2147755587"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 fa f7 f1 8b 8c 24 ?? ?? ?? ?? 80 c3 01 03 8c 24 00 8b 3d ?? ?? ?? ?? 89 8c 24 00 8a 3c 17 8b 4c 24 2c 8b 54 24 04 8a 0c 11 28 f9 8b 7c 24 28 88 0c 17 30 fb 8b 0c 24 88 5c 0c 37}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DEY_2147755640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DEY!MTB"
        threat_id = "2147755640"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 0f b6 4d ?? 89 45 ?? 8b 45 f0 0f b6 84 05 ?? ?? ?? ?? 03 c1 8b cb 99 f7 f9 8b 45 01 8a 8c 15 02 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = "3m2ly509XGedqCqhCjYmrrIQDs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DEZ_2147755648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DEZ!MTB"
        threat_id = "2147755648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 99 b9 63 11 00 00 f7 f9 8b 84 24 ?? ?? ?? ?? 40 89 84 24 00 8a 94 14 ?? ?? ?? ?? 30 54 03 ff}  //weight: 1, accuracy: Low
        $x_1_2 = "ieqYmUg7igLjuTJLBjD9RSg1WBaqonaM06" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PVW_2147755669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PVW!MTB"
        threat_id = "2147755669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 b9 8f 0a 00 00 99 f7 f9 8b 84 24 ?? ?? ?? ?? 8b 8c 24 ?? ?? ?? ?? 8a 94 14 ?? ?? ?? ?? 30 14 08 07 00 8a 84 14}  //weight: 1, accuracy: Low
        $x_1_2 = "fD7KT5xuaSjMTCgL1b6MfvgVCcgs1jnR5Bn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PVX_2147755670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PVX!MTB"
        threat_id = "2147755670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 85 ?? ?? ?? ?? 8a 8c 15 ?? ?? ?? ?? 30 08 07 00 0f b6 8d}  //weight: 1, accuracy: Low
        $x_1_2 = "oDC0Giq5Tdi0VqnrqwDIEGfYloJ5t5f8taGMnHY" ascii //weight: 1
        $x_1_3 = "LlhlBtXrE5jXhPSktxT1hsewg5Wtl7aJ4TnhbkGwtfpor5XWfSys7OH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_TT_2147755681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.TT!MSR"
        threat_id = "2147755681"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 2a 30 1c 31 42 3b d7 7c ?? 33 d2 41 3b c8 72}  //weight: 1, accuracy: Low
        $x_1_2 = "hTyvQKrlILsFbosm0cg2wUrEzFN165O" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PVY_2147755707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PVY!MTB"
        threat_id = "2147755707"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f9 8b 84 24 ?? ?? ?? ?? 83 c0 01 89 84 24 ?? ?? ?? ?? 8a 94 14 ?? ?? ?? ?? 30 54 03 ff 05 00 b9}  //weight: 1, accuracy: Low
        $x_1_2 = "Fau11RGUYfakKfhIw0TqRD8cWDArOH6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PVZ_2147755708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PVZ!MTB"
        threat_id = "2147755708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f9 8b 4c 24 ?? 8b 84 24 ?? ?? ?? ?? 8a 1c 01 8a 54 14 ?? 32 da 88 1c 01 05 00 b9}  //weight: 1, accuracy: Low
        $x_1_2 = "EEteMvKfWnKduJhMn14Bow6hPBZyoM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_OR_2147755746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.OR!MTB"
        threat_id = "2147755746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 d3 03 c2 99 b9 ?? ?? ?? ?? f7 f9 8b 4c 24 ?? 8b 44 24 ?? 41 89 4c 24 1c 8a 54 14 28 30 54 08 ff 3b ee 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DFA_2147755766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DFA!MTB"
        threat_id = "2147755766"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 45 0c 0f b6 94 15 ?? ?? ?? ?? 03 c2 8b 4d 10 99 f7 ff 8b bd ?? ?? ?? ?? 8a 84 15 00 30 04 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 40 b9 8e 0a 00 00 f7 f1 6a 00 6a 00 8b fa 33 d2 89 7d 08 8a 84 3d ?? ?? ?? ?? 0f b6 c8 88 45 0c 8b 85 ?? ?? ?? ?? 03 c1 b9 8e 0a 00 00 f7 f1}  //weight: 1, accuracy: Low
        $x_1_3 = "cQ6eck9e1dXeRfNwR0k49hKM8TRPVhfakh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DFB_2147755819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DFB!MTB"
        threat_id = "2147755819"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 0f b6 4d 0f 89 85 ?? ?? ?? ?? 8b 45 f0 0f b6 84 05 ?? ?? ?? ?? 03 c1 8b cb 99 f7 f9 8b 85 00 8a 8c 15 01 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = {57 53 ff 15 ?? ?? ?? ?? 8b f8 8b 45 ?? c1 e0 03 53 50 68 00 30 00 00 57 53 ff 15 ?? ?? ?? ?? 50 ff d6 8b f0}  //weight: 1, accuracy: Low
        $x_1_3 = "tupFYkLBHTjUs4J6FbrBOHqDC4a2h8bO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DFC_2147755823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DFC!MTB"
        threat_id = "2147755823"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 c1 99 b9 7b 0d 00 00 f7 f9 8b 45 e8 8a 4c 15 00 30 08}  //weight: 1, accuracy: High
        $x_1_2 = "p0Iz5Dr6z3R2o7SucTODAjx2aml2ArmmGn7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PVB_2147755849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PVB!MTB"
        threat_id = "2147755849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 45 ?? 8a 4c 15 00 30 08 04 00 0f b6 4d}  //weight: 1, accuracy: Low
        $x_1_2 = "JUfdH8ZQCYzvpU4rVcaHVrCcpsybbKCu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_UT_2147755877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.UT!MTB"
        threat_id = "2147755877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 8b ce 99 f7 f9 8b 45 14 8a 8c 15 ?? ?? ?? ?? 30 08 40 ff 4d 08 89 45 14 75 94 8b 45 10 5e 5b eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RAA_2147755949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RAA!MTB"
        threat_id = "2147755949"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 45 ?? 8a 4c 15 ?? 30 08 40 39 9d ?? ?? ?? ?? 89 45 ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = "p0Iz5Dr6z3R2o7SucTODAjx2aml2ArmmGn7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_LX_2147756264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.LX!MTB"
        threat_id = "2147756264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 4d 17 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 45 e8 8a 8c 15 ?? ?? ?? ?? 30 08 40 ff 4d e4 89 45 e8 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_TU_2147756272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.TU!MTB"
        threat_id = "2147756272"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 f9 8a 03 83 c4 04 8a 54 14 14 32 c2 88 03 43 4d 75 93 8b 84 24 ?? ?? ?? ?? 5b 5d 5e 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RBA_2147756295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RBA!MTB"
        threat_id = "2147756295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0b 8d 5b 04 33 ?? ?? 0f ?? ?? 66 ?? ?? 8b ?? c1 ?? ?? 8d ?? ?? 0f ?? ?? 66 ?? ?? ?? c1 ?? ?? 0f ?? ?? c1 ?? ?? 47 66 ?? ?? ?? 0f ?? ?? 66 ?? ?? ?? 3b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_LI_2147756297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.LI!MTB"
        threat_id = "2147756297"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 f9 8b 8c 24 ?? ?? ?? ?? 8a 04 31 8a 94 14 ?? ?? ?? ?? 32 c2 88 04 31 8b 84 24 ?? ?? ?? ?? 41 89 8c 24 ?? ?? ?? ?? 8b c8 48 85 c9 89 84 24 ?? ?? ?? ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_TK_2147756298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.TK!MTB"
        threat_id = "2147756298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 8b cb 99 f7 f9 8b 45 ?? 8a 8c 15 ?? ?? ?? ?? 30 08 40 ff 4d ?? 89 45 ?? ?? ?? ?? ?? ?? ?? 8b 45 ?? 5e 5b ?? ?? 33 c0 8b 4d ?? 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PX_2147756312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PX!MTB"
        threat_id = "2147756312"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d0 8b 45 ?? 0f b6 14 10 8b 45 ?? 0f b6 0c 08 33 ca}  //weight: 1, accuracy: Low
        $x_1_2 = {2b c1 03 05 ?? ?? ?? ?? 8b 55 ?? 2b c2 8b 4d ?? 8b 55 ?? 88 14 01 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PX_2147756312_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PX!MTB"
        threat_id = "2147756312"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 40 89 44 24 ?? 8a 54 14 ?? 30 50 ?? 39 b4 24 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 44 24 ?? 8b 8c 24 ?? ?? ?? ?? 64 89 0d ?? ?? ?? ?? 59 5f 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DFD_2147756324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DFD!MTB"
        threat_id = "2147756324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e8 0f b6 84 05 ?? ?? ?? ?? 0f b6 4d 17 03 c1 99 8b cb f7 f9 8b 45 e4 8a 8c 15 00 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = "coRCCJ72q3ph0lMYkn9de74NKy0ybNyyjxEXk8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DFD_2147756324_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DFD!MTB"
        threat_id = "2147756324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 99 f7 bd ?? ?? ?? ?? 0f b6 84 15 ?? ?? ?? ?? 8b 4d 10 03 8d ?? ?? ?? ?? 0f b6 11 33 d0 8b 45 10 03 85 02 88 10}  //weight: 1, accuracy: Low
        $x_1_2 = "LokV7D5jfri4VjHPd1mtV1ppNJqsGh58BjgmRoBDMEiwXFP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DFG_2147756449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DFG!MTB"
        threat_id = "2147756449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {59 59 8b 4c 24 14 0f b6 4c 0c 24 03 c1 b9 f1 18 00 00 99 f7 f9 8b 44 24 20 8a 4c 14 24 30 08}  //weight: 1, accuracy: High
        $x_1_2 = "jlsxI7Biw7svRjzhxne8ebdE8sn7tsUphBf6ch" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DFH_2147756450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DFH!MTB"
        threat_id = "2147756450"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 99 b9 23 13 00 00 f7 f9 8b 4c 24 18 8b 84 24 ?? ?? ?? ?? 8a 1c 01 8a 54 14 20 32 da 88 1c 01}  //weight: 1, accuracy: Low
        $x_1_2 = "kuPw6ykzUUID5wWBezn6vbo7pCsZ3qO1ivXp0C7O" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DFI_2147756451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DFI!MTB"
        threat_id = "2147756451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c9 03 c1 99 b9 8e 0a 00 00 f7 f9 0f b6 94 15 ?? ?? ?? ?? 30 53 ff}  //weight: 1, accuracy: Low
        $x_1_2 = "C5XpeozSHnVcaZZtq2L4efA43J4mg0Q2oTRTWtFI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DSB_2147756529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DSB!MTB"
        threat_id = "2147756529"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 45 ?? 8a 4c 15 00 30 08 04 00 0f b6 4d}  //weight: 1, accuracy: Low
        $x_1_2 = "2gaIO6Vxs6POdNnGrHYCAUorVrIHgAkfrh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DSC_2147756530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DSC!MTB"
        threat_id = "2147756530"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 8c 0d ?? ?? ?? ?? 0f b6 c3 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 85 ?? ?? ?? ?? 8a 8c 15 ?? ?? ?? ?? 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = "paSb37WrpTs3b0hmnOCiz9pcHbYzPXdBpOp4ql6gk" ascii //weight: 1
        $x_1_3 = "eufNaVR2wYM9P0tTG6pHIXHOrgMvm8wRpKY7bztT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DFJ_2147756538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DFJ!MTB"
        threat_id = "2147756538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 c1 99 8b cf f7 f9 8b 45 e8 8a 4c 15 00 30 08}  //weight: 1, accuracy: High
        $x_1_2 = "AGzj2GHmXQsuZqtgd5RPjGjj9nBPSL9l5AV6d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DSF_2147756711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DSF!MTB"
        threat_id = "2147756711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 45 00 8a 54 14 ?? 32 c2 88 45 00}  //weight: 1, accuracy: Low
        $x_1_2 = "8gpdpe1GhZnDlSqN9I1jMSfvw3wKN3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_RAB_2147756715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RAB!MTB"
        threat_id = "2147756715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 a2 18 00 00 f7 f9 83 c4 2c 45 0f b6 54 14 ?? 30 55 ?? 83 bc 24 ?? ?? ?? ?? 00 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = "xpZVwOEY0yqnCECpeqJsHfFAF6EckasDup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DSH_2147756718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DSH!MTB"
        threat_id = "2147756718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 03 8a 54 14 ?? 32 c2 88 03}  //weight: 1, accuracy: Low
        $x_1_2 = "OEAq8u6JtAzHWF6EzUpIf5gXNhmEX7H" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DFK_2147756738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DFK!MTB"
        threat_id = "2147756738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 c1 99 8b ce f7 f9 8b 45 f0 83 4d fc ff 8a 4c 15 00 30 08}  //weight: 1, accuracy: High
        $x_1_2 = "oUpQmzEO96Yowk9ebaH9M0ArHJEcqvWri" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DFK_2147756738_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DFK!MTB"
        threat_id = "2147756738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8a 94 04 ?? ?? ?? ?? 8b c2 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 9c 14 00 8b 54 24 18 32 1a}  //weight: 1, accuracy: Low
        $x_1_2 = "6g3tmwJOMIUNoqPsJtZjT4SWpUH2oYjW0mouzXm1cypFa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DSI_2147756790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DSI!MTB"
        threat_id = "2147756790"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 03 8a 54 14 ?? 32 c2 88 03}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5d 00 8b 44 24 ?? 8a 54 14 ?? 32 da 88 5d 00}  //weight: 1, accuracy: Low
        $x_1_3 = "MwVVRk0grf2BZqTiXLciAbw5dakv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DSJ_2147756791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DSJ!MTB"
        threat_id = "2147756791"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 84 34 ?? ?? ?? ?? 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 45 0f b6 94 14 ?? ?? ?? ?? 30 55}  //weight: 1, accuracy: Low
        $x_1_2 = "IWhzzUePl8mdPB0rmJiISAq1i" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_W_2147756851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.W!MTB"
        threat_id = "2147756851"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 4c 8a 4c 24 33 88 08 8a 4c 24 3e 8a 54 24 3f 8b 84 24 88 01 00 00 8b 74 24 2c 29 f0 89 84 24 88 01 00 00 30 ca 8b 84 24 78 01 00 00 88 10 8b 44 24 38 83 c0 25 89 44 24 6c 39 f0 0f 82 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DSL_2147756871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DSL!MTB"
        threat_id = "2147756871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 8b cf 99 f7 f9 8b 45 ?? 83 4d fc ff 8a 8c 15 ?? ?? ?? ?? 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = "QeeH0jw9arHJmnuy5JqUoZYw2wZu0JtqIIH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DFL_2147756891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DFL!MTB"
        threat_id = "2147756891"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 e6 c1 ea 05 6b d2 2e 8b c6 2b c2 8a 14 41 30 14 1e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DSN_2147756929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DSN!MTB"
        threat_id = "2147756929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 06 0f b6 d3 03 c2 99 8b f1 f7 fe 8b 45 ?? 8a 54 15 ?? 30 10}  //weight: 1, accuracy: Low
        $x_1_2 = "6KfcElF4tIKvuuWDwMnz3de2dghWSvcEhT96" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DFM_2147756967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DFM!MTB"
        threat_id = "2147756967"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 03 83 c4 18 8a 54 14 14 32 c2 88 03}  //weight: 1, accuracy: Low
        $x_1_2 = "nwaY2rn85D8YwVcyzxFeWKPU3M8l1b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DFM_2147756967_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DFM!MTB"
        threat_id = "2147756967"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 e6 8b c6 2b c2 d1 e8 03 c2 8b 54 24 0c c1 e8 05 6b c0 23 8b ce 2b c8 8a 04 11 30 04 3e}  //weight: 1, accuracy: High
        $x_1_2 = "bCuNUk*d|PQd7l#|W@1R@cK{P3j@GnqAaL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DSS_2147756972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DSS!MTB"
        threat_id = "2147756972"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bCuNUk*d|PQd7l#|W@1R@cK{P3j@GnqAaL" ascii //weight: 1
        $x_1_2 = "lj?K3ZH0Wfm%asKJT3oGg#b8C3popca5aXjjA4L" ascii //weight: 1
        $x_1_3 = "WIGRd5faqlP|e7~MZLWB%6PFjEJX$II" ascii //weight: 1
        $x_1_4 = "?SFgyq~Q}*X@puxSo63mN@jRh3COvZdyZZMDYC%k" ascii //weight: 1
        $x_1_5 = "LbxvrNg2crrKbj@pbyvsCKj7KuQpL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DFN_2147757118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DFN!MTB"
        threat_id = "2147757118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 c1 b9 7f 1a 00 00 99 f7 f9 8a 03 83 c4 08 8a 54 14 14 32 c2 88 03}  //weight: 1, accuracy: High
        $x_1_2 = {03 c1 b9 3a 17 00 00 99 f7 f9 8a 03 83 c4 08 8a 54 14 14 32 c2 88 03}  //weight: 1, accuracy: High
        $x_1_3 = "ZNhLquw4dMqWttElQt5EPN80KW9LtHFzXvIbCy" ascii //weight: 1
        $x_1_4 = "76SbDPbF9xMSJ0jSsiJ5Ym1KEGTtx74Bt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DSQ_2147757203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DSQ!MTB"
        threat_id = "2147757203"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 f9 8a 03 83 c4 08 8a 54 14 14 32 c2 88 03 05 00 b9}  //weight: 1, accuracy: Low
        $x_1_2 = "JA4rYixfKbCrYLsb5T1WhJAc3rwPwkPL5ak" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DSR_2147757204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DSR!MTB"
        threat_id = "2147757204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5d 00 8b 44 24 ?? 83 c4 10 8a 54 14 ?? 32 da 88 5d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DST_2147757470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DST!MTB"
        threat_id = "2147757470"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 07 0f b6 cb 03 c1 8b ce 99 f7 f9 8b 45 ?? 8a 8c 15 ?? ?? ?? ?? 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = "yWtGOEAPJfiQ5mvY1vUor47us65Y" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DSV_2147757543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DSV!MTB"
        threat_id = "2147757543"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 ab aa aa aa f7 e6 8b ce d1 ea 8d 04 52 2b c8 8a 44 0d ?? 30 86 ?? ?? ?? ?? 81 fe ?? ?? ?? ?? 72}  //weight: 2, accuracy: Low
        $x_1_2 = "YV3WN2J6YBMCGVID8UU" ascii //weight: 1
        $x_1_3 = "QZMJGG4MHPHK6EZG0ES" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_DFO_2147757614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DFO!MTB"
        threat_id = "2147757614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 c1 b9 7f 08 00 00 99 f7 f9 8b 44 24 20 8a 4c 14 24 30 08}  //weight: 1, accuracy: High
        $x_1_2 = "35te8nd3THAmrNVXQLY9zSDEJPc8t308R9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DSX_2147757618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DSX!MTB"
        threat_id = "2147757618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 34 ?? 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 83 c5 01 0f b6 54 14 ?? 30 55}  //weight: 1, accuracy: Low
        $x_1_2 = "ibV07k8OvLIc3CC9tQATn10nzXHS7aeU3yjUP6hk7y0O" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DFP_2147757735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DFP!MTB"
        threat_id = "2147757735"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e1 c1 ea 04 8d 04 92 03 c0 03 c0 8b d1 2b d0 8a 04 1a 30 04 31 [0-4] 3b cf 75}  //weight: 1, accuracy: Low
        $x_1_2 = "rDAzxssGAGddEASZD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DFQ_2147757867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DFQ!MTB"
        threat_id = "2147757867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 25 ff 00 00 00 8a 4c 14 20 8b ac 24 ?? ?? ?? ?? 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8b 4c 24 14 8a 04 29 8a 54 14 20 32 c2 88 04 29}  //weight: 1, accuracy: Low
        $x_1_2 = "i4HfVAKZB4P0peH30ieDMDyZUm7LvG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DFR_2147757868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DFR!MTB"
        threat_id = "2147757868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 4c 24 18 8b 84 24 ?? ?? ?? ?? 8a 1c 01 8a 54 14 1c 32 da 88 1c 01}  //weight: 1, accuracy: Low
        $x_1_2 = "FFgXYZiVR1YdrVLoWEnxqVBhS4wH4UgQKUX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PSA_2147757896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PSA!MTB"
        threat_id = "2147757896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 8b 4c 24 ?? 40 89 44 24 ?? 8a 54 14 ?? 30 54 01}  //weight: 1, accuracy: Low
        $x_1_2 = "zY7XTudRsOFLH5AHikcOb0qVFTYaSmkyrDsrU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PSC_2147757977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PSC!MTB"
        threat_id = "2147757977"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 04 ?? 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8b 44 24 ?? 8a 4c 14 ?? 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = "hWsJLqmB9M1aZsdikyPF417HVudJEuc5g1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PSG_2147758115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PSG!MTB"
        threat_id = "2147758115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 0c 8d 0c 06 33 d2 8b c6 f7 75 ?? 8b 45 ?? 8a 04 50 30 01 46 3b 75 ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = "A5ZjSQ421N3tjQG85iGjEjlSjOQLwPAsmNWyORaxp2166" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PSH_2147758116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PSH!MTB"
        threat_id = "2147758116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 34 ?? 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 83 c4 ?? 83 c5 01 0f b6 54 14 ?? 30 55}  //weight: 1, accuracy: Low
        $x_1_2 = "lebgSd3ERFImu61G2386CmFdN5E8nZloUgqH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PSK_2147758225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PSK!MTB"
        threat_id = "2147758225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 10 88 16 88 18 0f b6 06 0f b6 d3 03 c2 99 8b f1 f7 fe 8b 85 ?? ?? ?? ?? 8a 94 15 ?? ?? ?? ?? 30 10}  //weight: 1, accuracy: Low
        $x_1_2 = "fHwRkM1y0gdhUzm41LLSNytAbiP0EDjKJOGaQ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PSL_2147758226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PSL!MTB"
        threat_id = "2147758226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 10 88 16 88 18 0f b6 06 0f b6 d3 03 c2 99 8b f1 f7 fe 8b 85 ?? ?? ?? ?? 8a 94 15 ?? ?? ?? ?? 30 10}  //weight: 1, accuracy: Low
        $x_1_2 = "bhuxC*7dlDIWM^joU5M6m4vrXszrbp2J2NK7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PSN_2147758307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PSN!MTB"
        threat_id = "2147758307"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 16 0f b6 c3 03 c2 8b f1 99 f7 fe 8b 45 ?? 8a 94 15 ?? ?? ?? ?? 30 10}  //weight: 1, accuracy: Low
        $x_1_2 = "HsGuR2vR4FA9tuOLtaEuNjSxYYBZ7xEwoCE5WVwfwaD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DFS_2147758419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DFS!MTB"
        threat_id = "2147758419"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 10 88 16 88 18 0f b6 06 0f b6 d3 03 c2 99 8b f1 f7 fe 8b 45 f8 8a 94 15 ?? ?? ?? ?? 30 10}  //weight: 1, accuracy: Low
        $x_1_2 = "pRUbThH0IvjBI9aEfjFrDhEtQyM1WgM9fBGvC9NVoK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DFT_2147758420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DFT!MTB"
        threat_id = "2147758420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 10 88 16 88 18 0f b6 06 0f b6 d3 03 c2 99 8b f1 f7 fe 8b 45 ?? 8a 54 15 ?? 30 10}  //weight: 1, accuracy: Low
        $x_1_2 = "JXLg8G55wDncVAiIWelh43nRo38y5meHN4C" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PSO_2147758441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PSO!MTB"
        threat_id = "2147758441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 4c 24 ?? 89 84 24 ?? ?? ?? ?? 8b 44 24 ?? 0f b6 84 04 ?? ?? ?? ?? 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 84 24 ?? ?? ?? ?? 8a 8c 14 ?? ?? ?? ?? 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = "PfdJwZPEPVmRM8ODcEvetg69rIflA7LmmGZwlEdrJPA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PSQ_2147758497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PSQ!MTB"
        threat_id = "2147758497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 84 05 ?? ?? ?? ?? 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8b 45 ?? 8a 8c 15 ?? ?? ?? ?? 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = "AqNWZRPn8KPDx8YV6ADnuTis0M2ZmI71VnnQ8rwUg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PSR_2147758498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PSR!MTB"
        threat_id = "2147758498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 54 24 ?? 03 c2 99 b9 ?? ?? ?? ?? f7 f9 8b 4c 24 ?? 8b 44 24 ?? 83 c1 01 89 4c 24 ?? 8a 54 14 ?? 30 54 08}  //weight: 1, accuracy: Low
        $x_1_2 = "DOoLeArvYi0PutZkDjhTxeYq3zDAub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PST_2147758640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PST!MTB"
        threat_id = "2147758640"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 03 8a 94 14 ?? ?? ?? ?? 32 c2 88 03 07 00 8a 84 34}  //weight: 1, accuracy: Low
        $x_1_2 = "mn5oQFeypnaoNuVEJm5Pltjt0mafa8AwN1eqx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PSU_2147758641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PSU!MTB"
        threat_id = "2147758641"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5d 00 8a 54 14 ?? 32 da 88 5d 00}  //weight: 1, accuracy: Low
        $x_1_2 = "ywfTGtCMgwRJtgeUpm6r90c9Q1gkxJSQN32LnwGIwAE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PSV_2147758746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PSV!MTB"
        threat_id = "2147758746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 84 34 ?? ?? ?? ?? 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5d 00 8a 94 14 ?? ?? ?? ?? 32 da 88 5d 00}  //weight: 1, accuracy: Low
        $x_1_2 = "0dqkizLPblez73k0kCwMGqjfzp3rWgehEsFt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PSW_2147758747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PSW!MTB"
        threat_id = "2147758747"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 84 34 ?? ?? ?? ?? 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 83 c5 01 0f b6 94 14 ?? ?? ?? ?? 30 55}  //weight: 1, accuracy: Low
        $x_1_2 = "6SxWWnnZ0fczqvhpd41z0yn7bfBChTWOxhaFKhdVEx7ZK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_RAC_2147758818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RAC!MTB"
        threat_id = "2147758818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b9 53 1b 00 00 f7 f9 45 0f b6 94 14 ?? ?? ?? ?? 30 55 ?? 8b 84 24 ?? ?? ?? ?? 83 c0 ?? c7 84 24 ?? ?? ?? ?? 01 00 00 00 8d 48 ?? 83 ca ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DFU_2147758837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DFU!MTB"
        threat_id = "2147758837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ey4rC1bvNbf95Ddjm7uvhqyKH6BMrsYo3Hp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PSY_2147758861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PSY!MTB"
        threat_id = "2147758861"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 4c 24 ?? 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 83 c4 ?? 8a 4c 14 ?? 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = "0NH6NNGCdyptzLOAQ9iPC2ZM6SKDOriWAWIj9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PSZ_2147758862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PSZ!MTB"
        threat_id = "2147758862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 4c 24 ?? 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 83 c4 ?? 8a 4c 14 ?? 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = "IGLiVKBudntJqRIJK6qJGFKp4zLeUxEBqPrvmVXQT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DFV_2147758928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DFV!MTB"
        threat_id = "2147758928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5d 00 8d 4c 24 14 c7 84 24 ?? ?? ?? ?? ff ff ff ff 8a 94 14 ?? ?? ?? ?? 32 da 88 5d 00}  //weight: 1, accuracy: Low
        $x_1_2 = "dNMo4VqgprkMcQHi2r53ZLQLRuHgOS3EnPtVLe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DFW_2147758929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DFW!MTB"
        threat_id = "2147758929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8d 4c 24 18 83 c5 01 c7 84 24 ?? ?? ?? ?? ff ff ff ff 0f b6 94 14 ?? ?? ?? ?? 30 55 ff}  //weight: 1, accuracy: Low
        $x_1_2 = "29wxFvlyWdlUxIume3HTuh5AkFI5tM5kyO0rm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PDC_2147759050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PDC!MTB"
        threat_id = "2147759050"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 45 00 8a 94 14 ?? ?? ?? ?? 32 c2 88 45 00}  //weight: 1, accuracy: Low
        $x_1_2 = "M9L0rmb2BsgE6WsHY1DEqr4zqUGSqBg8n" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PDE_2147759095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PDE!MTB"
        threat_id = "2147759095"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 84 34 ?? ?? ?? ?? 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8d 4c 24 ?? 45 0f b6 94 14 ?? ?? ?? ?? 30 55}  //weight: 1, accuracy: Low
        $x_1_2 = "uiOtypAIS0KTQfa5pKj5ALbgaKAaMTHi5Zhp9RLLK9j" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PDD_2147759148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PDD!MTB"
        threat_id = "2147759148"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 07 0f b6 cb 03 c1 8b ce 99 f7 f9 8b 45 ?? 83 4d ?? ff 8a 8c 15 ?? ?? ?? ?? 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = "8x8NFrDblgVdz4aW7duGNZfOCw8V09QGM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DFX_2147759166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DFX!MTB"
        threat_id = "2147759166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 07 0f b6 cb 03 c1 8b ce 99 f7 f9 8b 45 14 83 4d fc ff 8a 8c 15 ?? ?? ?? ?? 30 08 [0-4] 8d 8d 00 89 45 14}  //weight: 1, accuracy: Low
        $x_1_2 = "mmZYGvGdE2r9h1eyXwCzcQ1UzoKytPp8sny6AqY1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PDF_2147759188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PDF!MTB"
        threat_id = "2147759188"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5d 00 8d 4c 24 ?? 8a 94 14 ?? ?? ?? ?? 32 da 88 5d 00}  //weight: 1, accuracy: Low
        $x_1_2 = "rCJgCcXMwff2O22WT2z988safYrxUbhFo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PDG_2147759196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PDG!MTB"
        threat_id = "2147759196"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 d3 03 c2 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 40 83 c4 0c 89 44 24 ?? 0f b6 54 14 ?? 30 50}  //weight: 1, accuracy: Low
        $x_1_2 = "ClEu0vQRU6jVFUb57izJ0ATu9tgs0K1CODAKmcZSE38VKQJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PDI_2147759362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PDI!MTB"
        threat_id = "2147759362"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 84 34 ?? ?? ?? ?? 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8d 4c 24 ?? 83 c5 01 0f b6 94 14 ?? ?? ?? ?? 30 55}  //weight: 1, accuracy: Low
        $x_1_2 = "RMrEiYg3R27tBL2zfR0qLbCGT5XMzxLYHmH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PDJ_2147759364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PDJ!MTB"
        threat_id = "2147759364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 d3 03 c2 99 b9 ?? ?? ?? ?? f7 f9 8b 85 ?? ?? ?? ?? 40 83 c4 0c 89 85 ?? ?? ?? ?? 0f b6 94 15 ?? ?? ?? ?? 30 50}  //weight: 1, accuracy: Low
        $x_1_2 = "gABupaeV9zawahoREO5222Vf31A6N7iPAE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DFY_2147759616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DFY!MTB"
        threat_id = "2147759616"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 8a 84 34 ?? ?? ?? ?? 81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 45 00 8a 94 14 00 32 c2 88 45 00}  //weight: 1, accuracy: Low
        $x_1_2 = "fNFMxIWaJF1HiBKnIHvHE5ZLLB5v2FYJATyW2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PDK_2147759643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PDK!MTB"
        threat_id = "2147759643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5d ?? 8d 4c 24 ?? 8a 94 14 ?? ?? ?? ?? 32 da 88 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PDL_2147759722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PDL!MTB"
        threat_id = "2147759722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 07 0f b6 cb 03 c1 99 8b ce f7 f9 8b 45 ?? 8a 4c 15 ?? 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = "r1FB2Wy1jrbCHaQLNsoPV7DHopVcXo6L" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PDM_2147759811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PDM!MTB"
        threat_id = "2147759811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8d 4c 24 ?? 83 c5 01 0f b6 94 14 ?? ?? ?? ?? 30 55}  //weight: 1, accuracy: Low
        $x_1_2 = "d45wh0YD8I2Iu5gplvlMePTTWc43pKa3oYKeJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DFZ_2147759823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DFZ!MTB"
        threat_id = "2147759823"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 07 0f b6 cb 03 c1 8b ce 99 f7 f9 8b 45 14 8a 8c 15 ?? ?? ?? ?? 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = "lTkoNkFqlyrld8tCy6KUmk9DZ5dWi457YmyFr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DGA_2147759824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DGA!MTB"
        threat_id = "2147759824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8a 94 0d ?? ?? ?? ?? 03 c2 99 f7 bd ?? ?? ?? ?? 8b 45 10 03 85 ?? ?? ?? ?? 8a 08 32 8c 15 00 8b 55 10 03 95 02 88 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "|Eri6o$*XJY0qRTjZrGLEZo~QS2MG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DGB_2147759825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DGB!MTB"
        threat_id = "2147759825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 d3 03 c2 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 10 83 c0 01 89 44 24 10 8a 54 14 1c 30 50 ff}  //weight: 1, accuracy: Low
        $x_1_2 = "DmN0|IhCx$IvDfESQxtYo1%Nq6re1|$" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PDO_2147759930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PDO!MTB"
        threat_id = "2147759930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 03 8a 94 14 ?? ?? ?? ?? 32 c2 88 03}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5d ?? 8a 94 14 ?? ?? ?? ?? 32 da 88 5d}  //weight: 1, accuracy: Low
        $x_1_3 = "m85t6L0KL08YOTL4LC8pTMREyrCPILTD7WgMho" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PDP_2147759942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PDP!MTB"
        threat_id = "2147759942"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c3 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8b 85 ?? ?? ?? ?? 8a 8c 15 ?? ?? ?? ?? 30 08 08 00 0f b6 8c 05}  //weight: 1, accuracy: Low
        $x_1_2 = "chqiTrZqioQ9WfpJCEZkZxBFjbAnrezsEXgZFUWB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PDQ_2147760028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PDQ!MTB"
        threat_id = "2147760028"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 f9 8a 03 8d 4c 24 ?? c7 84 24 ?? ?? ?? ?? ff ff ff ff 8a 94 14 ?? ?? ?? ?? 32 c2 88 03 05 00 b9}  //weight: 1, accuracy: Low
        $x_1_2 = "u9Jr9wOoLyEjqII7Hm7fktaeqHrA8Io4T0W8f4pX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PDR_2147760029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PDR!MTB"
        threat_id = "2147760029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 45 ?? 8a 94 14 ?? ?? ?? ?? 32 c2 88 45}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 45 0f b6 94 14 ?? ?? ?? ?? 30 55}  //weight: 1, accuracy: Low
        $x_1_3 = "Zzd2LK9vqYDLyWvrZ7F1VAQmt6Lr3o1OgEtf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PDT_2147760073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PDT!MTB"
        threat_id = "2147760073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5d ?? 8d 4c 24 ?? 8a 94 14 ?? ?? ?? ?? 32 da 88 5d}  //weight: 1, accuracy: Low
        $x_1_2 = "TK2YPLq8kz9VmxewBjy9rKxSQfgPYBtnsQy1QX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DGC_2147760088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DGC!MTB"
        threat_id = "2147760088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 07 0f b6 cb 03 c1 99 8b ce f7 f9 8b 85 ?? ?? ?? ?? 8a 8c 15 ?? ?? ?? ?? 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = "hxUJHGYQNPQcCgMhMyRCs0OhbWzXmoj6Y" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PDV_2147760163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PDV!MTB"
        threat_id = "2147760163"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 f9 8a 03 8d 4c 24 ?? c7 84 24 ?? ?? ?? ?? ff ff ff ff 8a 94 14 ?? ?? ?? ?? 32 c2 88 03 05 00 b9}  //weight: 1, accuracy: Low
        $x_1_2 = "VQohGTXL1sXo38wwkI2F8upNzrIXpE3jxi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PDW_2147760267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PDW!MTB"
        threat_id = "2147760267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 45 0f b6 94 14 ?? ?? ?? ?? 30 55}  //weight: 1, accuracy: Low
        $x_1_2 = "jL9gmfSmndWj8wmsILpolZHbSG0MJozn6QRrfGZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PDX_2147760346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PDX!MTB"
        threat_id = "2147760346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8d 4c 24 ?? 45 c7 84 24 ?? ?? ?? ?? ff ff ff ff 0f b6 94 14 ?? ?? ?? ?? 30 55}  //weight: 1, accuracy: Low
        $x_1_2 = "W1n5SrfVeGMMepv3FgOxIs7m6MpjQJqwgpboK2FpJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PDY_2147760347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PDY!MTB"
        threat_id = "2147760347"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8d 4c 24 ?? 83 c5 01 c7 84 24 ?? ?? ?? ?? ff ff ff ff 0f b6 94 14 ?? ?? ?? ?? 30 55}  //weight: 1, accuracy: Low
        $x_1_2 = "bifHkBiWgZQZQBhDRtv4hKn0IHfr0PmzMC0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DGD_2147760577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DGD!MTB"
        threat_id = "2147760577"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c9 03 c1 99 b9 7f 0a 01 00 f7 f9 8d 4c 24 18 8a 9c 14 ?? ?? ?? ?? 32 5d 00 e8 ?? ?? ?? ?? 88 5d 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Hqy1zDJFz24DSooDgbMZLYfXEhqx3R2XId3hDKC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DGE_2147760590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DGE!MTB"
        threat_id = "2147760590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 4d fc c1 e8 0d 83 e0 01 89 46 14 8b 45 10 89 46 1c 8b 45 14 89 46 20 8b 45 18 89 46 24 8b 45 1c 89 46 28 8b 45 d8 89 46 30}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DGE_2147760590_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DGE!MTB"
        threat_id = "2147760590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 85 ?? ?? ?? ?? 40 83 c4 1c 89 85 01 0f b6 94 15 ?? ?? ?? ?? 30 50 ff}  //weight: 1, accuracy: Low
        $x_1_2 = "gDvn27xXFaD6lpYuFTPLZQ0o8Je07EfrfNcDBV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DGF_2147760592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DGF!MTB"
        threat_id = "2147760592"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 c9 03 c1 99 b9 30 2a 01 00 f7 f9 8a 5c 14 1c 32 5d 00}  //weight: 1, accuracy: High
        $x_1_2 = "tsnQMWDs0bXQxKkXs6hIGavOPSqCYy0GY7NGe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PDZ_2147760601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PDZ!MTB"
        threat_id = "2147760601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 2c ?? 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 4c 24 ?? 8b b4 24 ?? ?? ?? ?? 8a 04 31 8a 54 14 ?? 32 c2 88 04 31}  //weight: 1, accuracy: Low
        $x_1_2 = "43I2s1UfEx9IihpOp25rTODaBRkdTu~rQzNJAGl5V" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PEA_2147760610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PEA!MTB"
        threat_id = "2147760610"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 03 83 c4 0c 8a 54 14 ?? 32 c2 88 03 04 00 8a 44 34}  //weight: 1, accuracy: Low
        $x_1_2 = "NAOT8bxj7hc7oAuAQqlL~WVH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DGH_2147760650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DGH!MTB"
        threat_id = "2147760650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e1 ff 00 00 00 03 c1 b9 74 59 01 00 99 f7 f9 8a 4d 00 8a 9c 14 ?? ?? ?? ?? 32 d9}  //weight: 1, accuracy: Low
        $x_1_2 = "5fJCTPMJEawB0V2ZG65Le9dcEpBiuIkXao6izlU" ascii //weight: 1
        $x_1_3 = {0f b6 94 0d ?? ?? ?? ?? 03 c2 99 f7 bd ?? ?? ?? ?? 0f b6 84 15 00 0f b6 8d ?? ?? ?? ?? 33 c8 88 8d 03 68 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_4 = "tsnQMWDs0bXQxKkXs6hIGavOPSqCYy0GY7NGe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DGI_2147760673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DGI!MTB"
        threat_id = "2147760673"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 4d 00 8a 5c 14 1c 32 d9 [0-6] 8b 44 24 14 83 c4 04 88 5d 00}  //weight: 1, accuracy: Low
        $x_1_2 = "XlJ2vDmMDFJlOr4j5ImKrGB4ycfmcKD" ascii //weight: 1
        $x_1_3 = "eIyX0uEVVkNVLaPUS4LqZPh3qOVVyaNE54d" ascii //weight: 1
        $x_1_4 = "EuWPcTdyYvEbwHv2BxZHkJ0hZGFwt4wUPxkGNPoqZZibHt5dZCbch" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PEB_2147760720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PEB!MTB"
        threat_id = "2147760720"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 34 ?? 0f b6 c9 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5c 14 ?? 32 5d 00}  //weight: 1, accuracy: Low
        $x_1_2 = "oPGm9XE3boOXJDqMFgOMmAAYSRORWADrNzO" ascii //weight: 1
        $x_1_3 = "XiauTfnOAcmKoX2lf6KgtILcjOkc5jvEX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PEC_2147760731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PEC!MTB"
        threat_id = "2147760731"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 8b ce 99 f7 f9 8b 45 ?? 8a 9c 15 ?? ?? ?? ?? 32 18}  //weight: 1, accuracy: Low
        $x_1_2 = {81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 4d 00 8a 5c 14 ?? 32 d9 04 00 8a 44 34}  //weight: 1, accuracy: Low
        $x_1_3 = "ZHQXCbxyDFY5jEPD9y9WQAgvBizAhSZiR2S1r" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PED_2147760742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PED!MTB"
        threat_id = "2147760742"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 34 ?? 0f b6 c9 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 4d 00 8a 5c 14 ?? 32 d9}  //weight: 1, accuracy: Low
        $x_1_2 = "YoO9q4uXZOVDYz0Ys1QKKXRTwe8TqBPoFODlFIi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DGJ_2147760803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DGJ!MTB"
        threat_id = "2147760803"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c9 03 c1 8b cb 99 f7 f9 8b 84 24 ?? ?? ?? ?? 8a 5c 14 24 8b 54 24 1c 32 1c 02}  //weight: 1, accuracy: Low
        $x_1_2 = "9xgnie4Osi9OhGgODWTxm5WTbow5g93HBH23fl75b3bWviADv" ascii //weight: 1
        $x_1_3 = "5TFLanYGAG24ZQeXnJE6xChjEgd57ZBo3OqTz5HmM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PEE_2147760900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PEE!MTB"
        threat_id = "2147760900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 d1 03 c2 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 8a 5c 14 ?? 8b 54 24 ?? 32 1c 02}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 44 04 ?? 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8b 44 24 ?? 8a 4c 14 ?? 30 08}  //weight: 1, accuracy: Low
        $x_1_3 = "SdxOJgpeM5kp5qt3v52Lc8rTzJgogtjzyDD" ascii //weight: 1
        $x_1_4 = "iro0h3ZuIA#jQ!&7cHqAx#!%U4CKgejKgrzy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PEF_2147760959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PEF!MTB"
        threat_id = "2147760959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 8b 8d ?? ?? ?? ?? 33 d2 8a 94 0d ?? ?? ?? ?? 03 c2 99 f7 bd ?? ?? ?? ?? 8a 85 ?? ?? ?? ?? 32 84 15 ?? ?? ?? ?? 88 85}  //weight: 1, accuracy: Low
        $x_1_2 = "cINp5NJqttSZsgfBEtJkzjqJqAgnMVNImWH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PEG_2147760964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PEG!MTB"
        threat_id = "2147760964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 f9 8a 4c 24 ?? 8b 84 24 ?? ?? ?? ?? 8a 94 14 ?? ?? ?? ?? 32 ca 85 c0 88 4c 24 0e 00 8a 84 14 ?? ?? ?? ?? 03 c1 b9}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 44 34 ?? 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 83 c5 01 0f b6 54 14 ?? 32 54 24}  //weight: 1, accuracy: Low
        $x_1_3 = "sfR1rITOyR43NeiuF25jmw5PIN4fTMQLVQLdAkb" ascii //weight: 1
        $x_1_4 = "Zxxm9gEBbYiHfQC61s4HyYSdkkTnBBrQ" ascii //weight: 1
        $x_1_5 = "eIVFuHu8M0xzEL99TcF4em4jSrrNFj6yf5if4Yvo4Ki7pR75apkf5i8DLbsIVKJGVSsH18xFnRm2j" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DGK_2147760970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DGK!MTB"
        threat_id = "2147760970"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 4b 40 b9 57 2b 01 00 f7 f1 8b 74 24 ?? 89 9c 24 ?? ?? ?? ?? 57 57 8b ca 8a 5c 0c ?? 0f b6 c3 03 c6 33 d2 be 57 2b 01 00 f7 f6}  //weight: 1, accuracy: Low
        $x_1_2 = "eIVFuHu8M0xzEL99TcF4em4jSrrNFj6yf5if4Yv" ascii //weight: 1
        $x_1_3 = "o4Ki7pR75apkf5i8DLbsIVKJGVSsH18xFnRm2j" ascii //weight: 1
        $x_1_4 = "OK5FvHZZ41KzE5rN64JPDYL80VwznVLKEY2pMAIJqIXtEjK" ascii //weight: 1
        $x_1_5 = "thuhT8TkgI74quSsam6yDxcRhltDlSsucXwaXGLPJwYHWuW9lLfGEUyHF7QaGLWc" ascii //weight: 1
        $x_1_6 = "1uLRDTeB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_DGL_2147761056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DGL!MTB"
        threat_id = "2147761056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 8b ce f7 f9 8b 45 8c 8a 4c 15 90 30 08}  //weight: 1, accuracy: High
        $x_1_2 = "Y%olT5sKZd@|~R4cXWitr{" ascii //weight: 1
        $x_1_3 = "wuyvbhirhbrihrgbrkbrkhr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_MB_2147761098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.MB!MTB"
        threat_id = "2147761098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b d2 65 0f b6 c9 03 d1 8a 48 01 40 84 c9 75 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_MB_2147761098_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.MB!MTB"
        threat_id = "2147761098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0c b7 03 4c 24 28 51 e8 ?? ?? ?? ?? 83 c4 ?? 3b 44 24 2c 74 1f 83 c6 ?? 3b 74 24 14 72 e1}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 8b c1 f7 f7 8a 5c 0c ?? 0f b6 c3 83 c1 01 0f b6 14 2a 03 d6 03 c2 33 d2 be ?? ?? ?? ?? f7 f6 81 f9 01 8b f2 8a 44 34 ?? 88 44 0c ?? 88 5c 34 ?? 72 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_MB_2147761098_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.MB!MTB"
        threat_id = "2147761098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dfadqkiov" ascii //weight: 1
        $x_1_2 = "dfaoopdqkiov" ascii //weight: 1
        $x_1_3 = "dgcghd" ascii //weight: 1
        $x_1_4 = "ggvdw" ascii //weight: 1
        $x_1_5 = "ComputerGraphics.dll" ascii //weight: 1
        $x_1_6 = "NoNetConnectDisconnect" ascii //weight: 1
        $x_1_7 = "GetDiskFreeSpaceA" ascii //weight: 1
        $x_1_8 = "LockFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DGM_2147761117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DGM!MTB"
        threat_id = "2147761117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 b9 b0 ff 00 00 f7 f1 56 56 8b ca 8a 5c 0c 30 0f b6 c3 03 c7 33 d2 bf b0 ff 00 00 f7 f7}  //weight: 1, accuracy: High
        $x_1_2 = "#KamS6TGNCfVR03K{GyO9Z|n4xj1$w9Tv" ascii //weight: 1
        $x_1_3 = "zZDequawg5BYNIzS6iuM1Q" ascii //weight: 1
        $x_1_4 = "eTNy24B%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_SF_2147761134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SF!MTB"
        threat_id = "2147761134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 00 8b c6 0d 00 02 00 00 81 e1 00 00 00 04 0f 44 c6 8b f0 8d 44 24 28 50 8b 45 e8 56 ff 75 ec 03 c3 50 ff 54 24 3c 85 c0 0f 84 ?? ?? ff ff 8b 44 24 24 83 c5 28 85 c0 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_2_2 = {8b d8 33 ff 8b 0b 8d 5b 04 33 4d f4 0f b6 c1 66 89 06 8b c1 c1 e8 08 8d 76 08 0f b6 c0 66 89 46 fa c1 e9 10 0f b6 c1 c1 e9 08 47 66 89 46 fc 0f b6 c1 66 89 46 fe 3b fa 72 ca}  //weight: 2, accuracy: High
        $x_2_3 = {8b 75 fc 8b 0b 8d 5b 04 33 4d f8 88 0a 8b c1 c1 e8 08 8d 52 04 c1 e9 10 88 42 fd 88 4a fe c1 e9 08 46 88 4a ff 3b f7 72 da}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GGG_2147761194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GGG!MTB"
        threat_id = "2147761194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 0d 00 10 00 00 50 57 53 ff 15 [0-4] 50 ff 54 [0-2] 8b f0 3b f3 74}  //weight: 1, accuracy: Low
        $x_1_2 = {57 56 83 e7 0f 83 e6 0f 3b fe 5e 5f}  //weight: 1, accuracy: High
        $x_1_3 = {8b 06 8b 4d [0-2] 5f 5e 64 [0-2] 00 00 00 00 5b c9 c2}  //weight: 1, accuracy: Low
        $x_1_4 = {6a ff 50 64 [0-2] 00 00 00 00 50 8b 44 [0-2] 64 [0-2] 00 00 00 00 89 6c [0-2] 8d 6c [0-2] 50 c3}  //weight: 1, accuracy: Low
        $x_10_5 = {8b f8 53 8d [0-12] c6 [0-3] 74 c6 [0-3] 61 c6 [0-3] 73 c6 [0-3] 6b c6 [0-3] 6d c6 [0-3] 67 c6 [0-3] 72 c6 [0-3] 2e c6 [0-3] 65 c6 [0-3] 78 c6 [0-3] 65 88 [0-3] ff}  //weight: 10, accuracy: Low
        $x_10_6 = "UnhookWindowsHookEx" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_DGN_2147761200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DGN!MTB"
        threat_id = "2147761200"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f2 33 d2 8a 8c 34 ?? ?? ?? ?? 8b c1 88 8c 24 ?? ?? ?? ?? 25 ff 00 00 00 03 c7 bf ?? ?? ?? ?? f7 f7 8b fa 8a 94 3c 00 88 94 34}  //weight: 1, accuracy: Low
        $x_1_2 = "MxNO#C6et#{EHG5a4Oj%zkf@2mU@CWWE" ascii //weight: 1
        $x_1_3 = "N9bkV|lJ?5zNZRe4aPbh}G}tq?g4Re@ntV" ascii //weight: 1
        $x_1_4 = "cE0WfWly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PEH_2147761246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PEH!MTB"
        threat_id = "2147761246"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8b 8c 24 ?? ?? ?? ?? 8a 84 14 ?? ?? ?? ?? 8b 54 24 ?? 32 04 0a 88 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = "FGMQVDF9SurFjPJFhNTFYcmPqV7wbH6W03tKziDDcEWBV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_GC_2147761295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GC!MTB"
        threat_id = "2147761295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 14 11 8b 4d ?? 0f b6 04 01 33 c2 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 0f af 35 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 0f af 3d ?? ?? ?? ?? 8b 5d ?? 03 1d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GC_2147761295_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GC!MTB"
        threat_id = "2147761295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c9 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 8a 0c 18 8a 14 32 32 d1 8d 4c 24 ?? 51 88 13}  //weight: 1, accuracy: Low
        $x_1_2 = "ATn*0Z$WX#0ovuKM{8Hau0i3peWcRl3HwC0L?*NtSh{rpk9SPda0gwzw15gR2ddeaRB1*Z?NJVxmPK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_GC_2147761295_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GC!MTB"
        threat_id = "2147761295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6b c6 44 24 ?? 65 c6 44 24 ?? 72 c6 44 24 ?? 6e c6 44 24 ?? 65 88 44 24 ?? c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e c6 44 24 ?? 64 [0-25] ff d5}  //weight: 10, accuracy: Low
        $x_3_2 = {6a 00 ff 15 [0-25] c6 [0-3] 74 c6 [0-3] 61 c6 [0-3] 73 c6 [0-3] 6b c6 [0-3] 6d c6 [0-3] 67 c6 [0-3] 72 c6 [0-3] 2e c6 [0-3] 65 c6 [0-3] 78 c6 [0-3] 65 [0-6] ff}  //weight: 3, accuracy: Low
        $x_3_3 = {8b f8 53 8d [0-12] c6 [0-3] 74 c6 [0-3] 61 c6 [0-3] 73 c6 [0-3] 6b c6 [0-3] 6d c6 [0-3] 67 c6 [0-3] 72 c6 [0-3] 2e c6 [0-3] 65 c6 [0-3] 78 c6 [0-3] 65 88 [0-3] ff}  //weight: 3, accuracy: Low
        $x_1_4 = "GetCurrentProcess" ascii //weight: 1
        $x_1_5 = "UnhookWindowsHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_DGO_2147761505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DGO!MTB"
        threat_id = "2147761505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8d 4c 24 18 83 c5 01 0f b6 94 14 ?? ?? ?? ?? 32 54 24 13 88 55 ff}  //weight: 1, accuracy: Low
        $x_1_2 = "X7{yIX3FqMICehf2%w0cREiaaKZBMKGbAw6ziu@grqh" ascii //weight: 1
        $x_1_3 = "qBQe83SLHx|~gTlEslYz~Buc$R4R2EDqMzT|h" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PEI_2147761542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PEI!MTB"
        threat_id = "2147761542"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 84 34 ?? ?? ?? ?? 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5c 24 ?? 8d 4c 24 ?? 8a 94 14 ?? ?? ?? ?? 32 d3 88 55}  //weight: 1, accuracy: Low
        $x_1_2 = "FkjCzpSs4CMIigGWivsHBF9ei" ascii //weight: 1
        $x_1_3 = "J68kCQshY7}hbvO$iWp1FM%c6%lyp2ku" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_GD_2147761570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GD!MTB"
        threat_id = "2147761570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b c8 0f af cb 8d 04 7f 03 d1 2b d0 8b 44 24 ?? 8a 18 8a 0c 32 32 d9 8b 4c 24 ?? 88 18 8b 44 24 ?? 40 3b c1 89 44 24 ?? 0f 82}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GD_2147761570_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GD!MTB"
        threat_id = "2147761570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c0 03 c2 99 f7 fb 0f b6 44 14 ?? 32 44 2e ?? 83 6c 24 [0-16] 88 46}  //weight: 1, accuracy: Low
        $x_1_2 = "nVchmJhwRR%!@JizO9rZmCJTUok$X5T&3O@Hecu14AJ!phRhYj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_GD_2147761570_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GD!MTB"
        threat_id = "2147761570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 db 57 53 [0-15] c6 [0-3] 6b c6 [0-3] 65 c6 [0-3] 72 c6 [0-3] 6e c6 [0-3] 65 c6 [0-3] 6c c6 [0-3] 33 c6 [0-3] 32 c6 [0-3] 2e c6 [0-3] 64 c6 [0-3] 6c c6 [0-3] 6c [0-15] ff}  //weight: 2, accuracy: Low
        $x_2_2 = {ff d6 33 f6 [0-12] c6 [0-3] 74 c6 [0-3] 61 c6 [0-3] 73 c6 [0-3] 6b c6 [0-3] 6d c6 [0-3] 67 c6 [0-3] 72 c6 [0-3] 2e c6 [0-3] 65 c6 [0-3] 78 c6 [0-3] 65 [0-15] ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GE_2147761583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GE!MTB"
        threat_id = "2147761583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 14 2f 03 c2 33 d2 f7 35 [0-4] 58 2b c1 0f af c3 03 d0 8b 44 24 ?? 2b d6 8a 0c 3a 30 08 ff 44 24 ?? 8b 44 24 ?? 3b 44 24 ?? 0f 82}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GE_2147761583_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GE!MTB"
        threat_id = "2147761583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b c6 44 24 [0-10] 72 c6 44 [0-2] 6e [0-10] c6 44 [0-2] 33 c6 44 [0-2] 32 c6 44 [0-2] 2e c6 44 [0-2] 64 [0-15] ff [0-6] 8b f0}  //weight: 1, accuracy: Low
        $x_1_2 = {78 c6 44 24 [0-2] 65 [0-12] ff 50 00 c6 [0-3] 74 c6 [0-3] 61 c6 [0-3] 73 c6 [0-3] 6b c6 [0-3] 6d c6 [0-3] 67 c6 [0-3] 72 c6 [0-3] 2e c6 [0-3] 65 c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GOG_2147761593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GOG!MTB"
        threat_id = "2147761593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_2 = {ff d6 33 f6 [0-12] c6 [0-3] 74 c6 [0-3] 61 c6 [0-3] 73 c6 [0-3] 6b c6 [0-3] 6d c6 [0-3] 67 c6 [0-3] 72 c6 [0-3] 2e c6 [0-3] 65 c6 [0-3] 78 c6 [0-3] 65 [0-15] ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PEJ_2147761712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PEJ!MTB"
        threat_id = "2147761712"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 b4 04 [0-4] 88 54 0c ?? 8a 54 04 ?? 0f b6 fa 03 f1 03 fe 8b cf 81 e1 ff 00 00 80 88 5c 04}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 5c 34 ?? 0f b6 d2 03 da 81 e3 ff 00 00 80 79 ?? 4b 81 cb ?? ?? ?? ?? 43 8a 54 1c ?? 32 14 0f 88 11}  //weight: 1, accuracy: Low
        $x_1_3 = "#4KPqh1pHLbhhKMPmuOW11%GIe$QM01JZfpUBLxxmaTFv$NnDMQFp3ldNV}kbexEAPsnXXQx4syu@c~$@qxLEfTAI?t4g%ZqSAz1*9shNbQp}9?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PEK_2147761848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PEK!MTB"
        threat_id = "2147761848"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 d2 03 d3 81 e2 ?? ?? ?? ?? 79 ?? 4a 81 ca 00 ff ff ff 42 0f b6 54 14 ?? 32 14 0f 41 83 ed 01 88 51}  //weight: 1, accuracy: Low
        $x_1_2 = "ZWFK%p@Wu}WA{bCPE9hXT?GXQLKwF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PEL_2147761940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PEL!MTB"
        threat_id = "2147761940"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 16 03 ca 81 e1 ?? ?? ?? ?? 79 ?? 49 81 c9 00 ff ff ff 41 8a 8c 0d ?? ?? ?? ?? 8b 55 ?? 32 0c 3a 88 0f}  //weight: 1, accuracy: Low
        $x_1_2 = "0WmfLjNQIqUtwtvadlxNXC?y~xbeK~$uLkOQa%?~Wj4a3#Lu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PEM_2147761946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PEM!MTB"
        threat_id = "2147761946"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 07 0f b6 cb 03 c1 8b ce 99 f7 f9 8b 45 ?? 8a 8c 15 ?? ?? ?? ?? 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = "05aOPJsAs53PFvbwXkTkwvLpCBbx7qkvnfhaBYxZEsv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PEN_2147761947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PEN!MTB"
        threat_id = "2147761947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d3 81 e2 ?? ?? ?? ?? 79 ?? 4a 81 ca 00 ff ff ff 42 8a 54 14 ?? 8a 1c 0f 32 d3 88 11 04 00 8a 54 34}  //weight: 1, accuracy: Low
        $x_1_2 = "TklQ6Zr%7Pb$7r*0rHpUhAexjID4j4QC2kjIF{GdR2HB2l8JgiMN%bm54jiSd*U$MOwN@Zrn1u9@G$VZLtkehuu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PEO_2147762011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PEO!MTB"
        threat_id = "2147762011"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 81 c9 00 ff ff ff 41 0f b6 44 0c ?? 8b 4c 24 ?? 32 04 19 83 c3 01 83 6c 24 ?? 01 88 43 ff}  //weight: 1, accuracy: Low
        $x_1_2 = "Q46EPI4CgnF96ok17@UleR%s@$wYDXQOj8v@}ZlyqA7Y~Vu~zQ$*IB$LPFM2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PEP_2147762012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PEP!MTB"
        threat_id = "2147762012"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 02 8b 54 24 ?? 32 4c 14 ?? 40 83 6c 24 ?? 01 88 48 ff 89 44 24 08 00 8b 44 24 ?? 8b 54 24}  //weight: 1, accuracy: Low
        $x_1_2 = "Eu*lA5Z|p#EzZVCPC~qtLn*vRbRPbM~L#9dgSzR}eDx$E9H2zonbFtc#j87r}kWSLgG{" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PEQ_2147762013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PEQ!MTB"
        threat_id = "2147762013"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4a 81 ca 00 ff ff ff 42 8a 4c 14 ?? 8b 54 24 ?? 32 0c 1a 8b 44 24 ?? 88 0b}  //weight: 1, accuracy: Low
        $x_1_2 = "Ph}u$|8rvCsw873~dkBf?IM?vuZTljVtYBNmAXZ6%l|DWHHqVotDfxQSJnd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_SE_2147762099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SE!MTB"
        threat_id = "2147762099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 33 e2 89 45 ?? 81 45 ?? ?? ?? ?? ?? 81 45 ?? ?? ?? ?? ?? 81 75 ?? ?? ?? ?? ?? 8a 4d ?? 8b 7d ?? 0f b7 06 d3 e7 83 f8 41 72 08 83 f8 5a 77 03 83 c0 20 89 45 ?? 83 c6 02 01 55 ?? 33 c0 01 7d ?? 29 5d ?? 66 39 06 0f 85 ?? ff ff ff 5f 5b 8b 45 ?? 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 8b d6 8d 0c bb 8b f9 2b fb 83 c7 03 c1 ef 02 3b d9 0f 47 f8 85 ff 74 2c 8b 75 ?? 8b 0b 8d 5b 04 33 4d ?? 88 0a 8b c1 c1 e8 08 8d 52 04 c1 e9 10 88 42 ?? 88 4a ?? c1 e9 08 46 88 4a ?? 3b f7 72 da}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PER_2147762100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PER!MTB"
        threat_id = "2147762100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 01 8b 4c 24 ?? 32 54 0c ?? 40 88 50 ff 89 44 24 08 00 8b 44 24 ?? 8b 4c 24}  //weight: 1, accuracy: Low
        $x_1_2 = "jW5f1JNBfDuu$9Nr|w6h9dS01d{XO1Q{~xW*dIocZyZBSG50~{JOD@5GPLK@dXTPiFp|%1L20rDBrQB9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PES_2147762104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PES!MTB"
        threat_id = "2147762104"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 01 8b 4c 24 ?? 32 54 0c ?? 88 10 40 89 44 24 08 00 8b 44 24 ?? 8b 4c 24}  //weight: 1, accuracy: Low
        $x_1_2 = "KbVvUksdpKsP1bNZkoQoW@R$3rp*{X~9*Q2k0q*RmWRcevDYG6%W~cNeKNGZ$G8*2U0*3c6w3M#?E" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PET_2147762113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PET!MTB"
        threat_id = "2147762113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 02 8b 54 24 ?? 32 4c 14 ?? 83 c0 01 83 6c 24 ?? 01 88 48 ff 89 44 24 08 00 8b 44 24 ?? 8b 54 24}  //weight: 1, accuracy: Low
        $x_1_2 = "D}Y${ElPDqgV58%bKT94%GJPOQE9CnAuhSzncHpFvufD4%jrQdI08o0At6i$N?aLDAaN$" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_X_2147762182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.X!MTB"
        threat_id = "2147762182"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 1c 8b 74 24 10 8a 14 31 8b 44 24 18 32 94 04 ?? ?? ?? ?? 8d 4c 24 20 88 16 c7 84 24 ?? ?? ?? ?? ff ff ff ff e8 ?? ?? ff ff 8b 44 24 14 46 48 89 74 24 10 89 44 24 14 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 f9 89 95 ?? ?? ?? ff 8b 55 08 03 95 ?? ?? ?? ff 33 c0 8a 02 8b 8d ?? ?? ?? ff 33 d2 8a 94 0d ?? ?? ?? ff 33 c2 8b 4d 18 03 8d ?? ?? ?? ff 88 01 e9 ?? ff ff ff 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_3 = {f7 f9 8b 44 24 14 8a 0c 18 8a 14 32 32 d1 8d 4c 24 2c 51 88 13 e8 ?? ?? ff ff 8b 44 24 10 43 48 89 44 24 10 75 ?? 5f 5e 5d 5b 81 c4 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
        $x_1_4 = {f7 f9 8b 44 24 14 8a 0c 18 8a 14 32 32 d1 8d 4c 24 2c 88 13 e8 ?? ?? ff ff 8b 44 24 10 43 48 89 44 24 10 75 ?? 5f 5e 5d 5b 81 c4 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
        $x_1_5 = {33 c0 8a 04 0f 81 e2 ff 00 00 00 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8a 04 0a 8a 14 2b 32 c2 88 03 8b 44 24 28 43 48 89 44 24 28 75 ?? 5f 5e 5d 5b 83 c4 08 c3}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 4c 24 24 0f b6 14 39 0f b6 04 2f 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 44 24 10 8a 0c 3a 8b 54 24 18 32 0c 02 88 08 40 89 44 24 10 ff 4c 24 14 0f 85 ?? ?? ff ff 5f 5e 5d 5b 83 c4 0c c3}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 4d fc 03 4d e8 33 d2 8a 11 03 c2 33 d2 f7 35 ?? ?? ?? ?? 89 55 f8 a1 ?? ?? ?? ?? 8b 08 8b 55 08 33 c0 8a 04 0a 8b 4d fc 03 4d f8 33 d2 8a 11 33 c2 8b 0d ?? ?? ?? ?? 8b 11 8b 4d 18 88 04 11 e9 ?? ff ff ff 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_8 = {0f b6 04 0e 0f b6 d2 03 c2 33 d2 f7 35 ?? ?? ?? ?? 0f b6 04 0a 8b 54 24 1c 32 04 13 8b 54 24 28 88 04 13 a1 ?? ?? ?? ?? 83 c0 01 3b c5 a3 ?? ?? ?? ?? 72 ?? 5f 5e 5d 5b 83 c4 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PEU_2147762184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PEU!MTB"
        threat_id = "2147762184"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 54 3c ?? 0f b6 c0 03 c2 99 f7 fb 8a 1c 2e 8a 44 14 ?? 32 c3 88 06}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 14 31 8b 44 24 ?? 32 94 04 ?? ?? ?? ?? 8d 4c 24 ?? 88 16 c7 84 24 ?? ?? ?? ?? ff ff ff ff 08 00 8b 4c 24 ?? 8b 74 24}  //weight: 1, accuracy: Low
        $x_1_3 = "6tm*PQtTP8k1nG3kms?M4{wFUuw%y|97D4pgGNwl63@QWwBrO|ix4xBiT1$r$rOHS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_ARK_2147762194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.ARK!MTB"
        threat_id = "2147762194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4d 00 8d 6d 04 33 cf 0f b6 c1 66 89 06 8b c1 c1 e8 08 [0-31] c1 e9 10 0f b6 c1 c1 e9 08 43 [0-15] 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PEV_2147762303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PEV!MTB"
        threat_id = "2147762303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 89 95 ?? ?? ?? ?? 8b 55 ?? 03 95 ?? ?? ?? ?? 33 c0 8a 02 8b 8d ?? ?? ?? ?? 33 d2 8a 94 0d ?? ?? ?? ?? 33 c2 8b 4d ?? 03 8d ?? ?? ?? ?? 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = "OXYN|ia}PqgO?w6Niv{NlrJXpUj|9O6WPoxp75omgVMJ5$je*@5KG{PEnCM*Xg9Nr55yiYHay" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PEW_2147762307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PEW!MTB"
        threat_id = "2147762307"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e2 ff 00 00 00 03 c2 99 f7 fb 8a 1c 2e 8a 44 14 ?? 32 c3 88 06 04 00 8a 44 3c}  //weight: 1, accuracy: Low
        $x_1_2 = "j9CFVex333dAy*2?Bqxx8XAOjToonUvCj8n{QUdt1KjCCjeKAO%pHJcp4}0ko7xRrDXq%UmtEWCC0aeyfe@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PEX_2147762373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PEX!MTB"
        threat_id = "2147762373"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 31 0f b6 c0 03 c2 99 bf ?? ?? ?? ?? f7 ff 8a 04 32 32 04 2b 88 03}  //weight: 1, accuracy: Low
        $x_1_2 = "M@~JSRPu@Pa5sM?V2I5SLdDdRWxqxHiq~n68nP0#B~V0M2izw6?q6G0A*2JjxAqt}cd820D#8tk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_SG_2147762422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SG!!Emotet.gen!MTB"
        threat_id = "2147762422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "Emotet: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 33 e2 89 45 ?? 81 45 ?? ?? ?? ?? ?? 81 45 ?? ?? ?? ?? ?? 81 75 ?? ?? ?? ?? ?? 8a 4d ?? 8b 7d ?? 0f b7 06 d3 e7 83 f8 41 72 08 83 f8 5a 77 03 83 c0 20 89 45 ?? 83 c6 02 01 55 ?? 33 c0 01 7d ?? 29 5d ?? 66 39 06 0f 85 ?? ff ff ff 5f 5b 8b 45 ?? 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 8b d6 8d 0c bb 8b f9 2b fb 83 c7 03 c1 ef 02 3b d9 0f 47 f8 85 ff 74 2c 8b 75 ?? 8b 0b 8d 5b 04 33 4d ?? 88 0a 8b c1 c1 e8 08 8d 52 04 c1 e9 10 88 42 ?? 88 4a ?? c1 e9 08 46 88 4a ?? 3b f7 72 da}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PEY_2147762429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PEY!MTB"
        threat_id = "2147762429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 0e 81 e2 ff 00 00 00 03 c2 99 f7 fd 8a 04 0a 8b 54 24 ?? 32 04 1a 43 88 43}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 00 0f b6 d2 03 c2 99 f7 fb 8a 04 0a 8b 55 ?? 32 04 3a 88 07}  //weight: 1, accuracy: Low
        $x_1_3 = "6u0CHm87msHhdX|z7cJGr0O0{L?yv?tOOV8W7LX~Zx~1pDRrifx62pyqtB*hKQ1937{j#zYfl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PEZ_2147762447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PEZ!MTB"
        threat_id = "2147762447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 02 8b 4d ?? 03 4d ?? 33 d2 8a 11 33 c2 8b 4d ?? 03 8d ?? ?? fe ff 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = "5$%zMx~KSOi?g~$wLhCy7M0QE2MaQ*DBW?r9Dn?u%NwGA#mSh7oXMS||%*SkTy#g{BCSrMx?ZqzU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PBA_2147762488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PBA!MTB"
        threat_id = "2147762488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 0e 0f b6 d2 03 c2 33 d2 f7 35 ?? ?? ?? ?? 0f b6 04 0a 32 44 2b ?? 83 6c 24 ?? 01 88 45}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 04 0f 0f b6 d2 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8a 04 0a 32 04 2b 88 45}  //weight: 1, accuracy: Low
        $x_1_3 = "?I53YwTXOI8sIRkup%#XPbWJ?J@jRWuC?O4mB#9debhgeMWNUICH9NKghsErHr%{P?V|5u1V" ascii //weight: 1
        $x_1_4 = "Gp}loZTPCsbfZm}B4l5Z~nbu|DQb*nzyx1}z@v4#~ac$bciftnmpY{@MVpN{Fuq3elBd}3caALl}IdHJkse" ascii //weight: 1
        $x_1_5 = "yumZOBkBY$HWENabDlF%irJY}u36O1d|j6P?des$ltwatM@V0pYZh2c2h#T|VbYS%GeyJRXIcF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PPP_2147762495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PPP!MTB"
        threat_id = "2147762495"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c9 03 c1 99 b9 ?? ?? ?? ?? f7 f9 0f b6 94 15 ?? ?? ?? ?? 30 53 ff}  //weight: 1, accuracy: Low
        $x_1_2 = "C5XpeozSHnVcaZZtq2L4efA43J4mg0Q2oTRTWtFI" ascii //weight: 1
        $x_1_3 = {0f b6 84 05 ?? ?? ?? ?? 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8b 45 ?? 8a 8c 15 ?? ?? ?? ?? 30 08}  //weight: 1, accuracy: Low
        $x_1_4 = "438lo77oQYpKG6zYOdrbakPrElMlTfq6ZGLHPGtX" ascii //weight: 1
        $x_1_5 = {81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 03 8a 54 14 ?? 32 c2 88 03}  //weight: 1, accuracy: Low
        $x_1_6 = "ycUwQ0itCGqtOp5K4vRfItYmO9vPDiBfq59aTDoWTxP" ascii //weight: 1
        $x_1_7 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5d 00 8b 44 24 ?? 8a 54 14 ?? 32 da 88 5d 00}  //weight: 1, accuracy: Low
        $x_1_8 = "DN320fr4ZdpExnvWQFN40RQrHwbKI6wmOe0C83s" ascii //weight: 1
        $x_1_9 = {0f b6 8c 05 ?? ?? ?? ?? 0f b6 c3 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8b 85 ?? ?? ?? ?? 8a 8c 15 ?? ?? ?? ?? 30 08}  //weight: 1, accuracy: Low
        $x_1_10 = "K85QYO7FJ8zpY8k59z4OzBv8WQ2IWd5KU4pGt" ascii //weight: 1
        $x_1_11 = {0f b6 8c 05 ?? ?? ?? ?? 0f b6 c3 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 85 ?? ?? ?? ?? 8a 8c 15 ?? ?? ?? ?? 30 08}  //weight: 1, accuracy: Low
        $x_1_12 = "IFadiUBblcDobFImfd54oq7dyKdNJAtyQfyzgz" ascii //weight: 1
        $x_1_13 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 83 c4 ?? 83 c5 01 0f b6 54 14 ?? 30 55}  //weight: 1, accuracy: Low
        $x_1_14 = "JA4rYixfKbCrYLsb5T1WhJAc3rwPwkPL5ak" ascii //weight: 1
        $x_1_15 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 8b 4c 24 ?? 40 89 44 24 ?? 8a 54 14 ?? 30 54 01}  //weight: 1, accuracy: Low
        $x_1_16 = "QUZePWMrwDxPfmNb7nRa3QZ1sC1TcwQmoJZ" ascii //weight: 1
        $x_1_17 = {0f b6 16 0f b6 c3 03 c2 8b f1 99 f7 fe 8b 45 ?? 8a 94 15 ?? ?? ?? ?? 30 10}  //weight: 1, accuracy: Low
        $x_1_18 = "yKemp20dO45SNNTOWED7NLxRQMrkyPHfAf" ascii //weight: 1
        $x_1_19 = {0f b6 44 14 ?? 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 4c 24 ?? 8b 44 24 ?? 83 c1 01 89 4c 24 ?? 8a 54 14 ?? 30 54 08}  //weight: 1, accuracy: Low
        $x_1_20 = {0f b6 44 14 ?? 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 4c 24 ?? 8b 84 24 ?? ?? ?? ?? 8a 1c 01 8a 54 14 ?? 32 da 88 1c 01}  //weight: 1, accuracy: Low
        $x_1_21 = "UkhR1Bg5lkJKmVfByNdNkBaAOeoimXOvKE5Rob8" ascii //weight: 1
        $x_1_22 = {0f b6 84 35 ?? ?? ?? ?? 0f b6 c9 03 c1 99 b9 ?? ?? ?? ?? f7 f9 0f b6 94 15 ?? ?? ?? ?? 30 53 ff}  //weight: 1, accuracy: Low
        $x_1_23 = "j5T910HSZZJoJ4lvoHmIbx8Z7wY0Cs2spd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_VVV_2147762496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.VVV!MTB"
        threat_id = "2147762496"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 ff 00 00 00 bb ?? ?? ?? ?? 03 c2 99 f7 fb 8a 1f 8a 44 14 ?? 32 d8 88 1f}  //weight: 1, accuracy: Low
        $x_1_2 = "T6srp6TPcP8bQA4Pm838Cbvsk2PN8D" ascii //weight: 1
        $x_1_3 = {81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 45 00 8a 94 14 ?? ?? ?? ?? 32 c2 88 45 00}  //weight: 1, accuracy: Low
        $x_1_4 = "7WZGa9nNSL23lyisKfiWDMw9prB5TdBL" ascii //weight: 1
        $x_1_5 = {0f b6 c3 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 85 ?? ?? ?? ?? 8a 8c 15 ?? ?? ?? ?? 30 08}  //weight: 1, accuracy: Low
        $x_1_6 = "61iX5wo3s4R2V0NGzTxNYRJNinFtFMPhHk650" ascii //weight: 1
        $x_1_7 = {99 f7 f9 8a 03 8d 4c 24 ?? c7 84 24 ?? ?? ?? ?? ff ff ff ff 8a 94 14 ?? ?? ?? ?? 32 c2 88 03 05 00 b9}  //weight: 1, accuracy: Low
        $x_1_8 = "iscE34zRyHvR9a4FT845Vzfy1KU804hDEi" ascii //weight: 1
        $x_1_9 = {0f b6 44 04 ?? 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8b 44 24 ?? 8a 4c 14 ?? 30 08}  //weight: 1, accuracy: Low
        $x_1_10 = "Qw31pmxECJxQy2m75lM5i5lAwzVgcjrcimotXD" ascii //weight: 1
        $x_1_11 = "ujW0OCy0PptB4ZuxMUEMx2RSu50mVORaz4s0JiX" ascii //weight: 1
        $x_1_12 = {0f b6 4c 24 ?? 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 4c 24 ?? 8b 44 24 ?? 83 c1 01 89 4c 24 ?? 8a 54 14 ?? 30 54 08}  //weight: 1, accuracy: Low
        $x_1_13 = "elhu52o040JLOJtpz7DNayKROrMpJjNrY" ascii //weight: 1
        $x_1_14 = {0f b6 d3 03 c2 99 b9 ?? ?? ?? ?? f7 f9 8b 4c 24 ?? 8b 44 24 ?? 83 c1 01 89 4c 24 ?? 8a 54 14 ?? 30 54 08}  //weight: 1, accuracy: Low
        $x_1_15 = "p1bEDh6FAoRKhjyczgsawyM0SYnNB33uBLlGFI" ascii //weight: 1
        $x_1_16 = {03 c2 8b ac 24 ?? ?? ?? ?? 99 f7 f9 8b 8c 24 ?? ?? ?? ?? 8a 04 29 8a 94 14 ?? ?? ?? ?? 32 c2 88 04 29 05 00 b9}  //weight: 1, accuracy: Low
        $x_1_17 = {0f b6 44 04 ?? 0f b6 4c 24 ?? 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 4c 24 ?? 8b 84 24 ?? ?? ?? ?? 8a 54 14 ?? 30 14 01}  //weight: 1, accuracy: Low
        $x_1_18 = "X8VMH59X8kmM9v0BudI#Kdq%v*lC5f0V" ascii //weight: 1
        $x_1_19 = {0f b6 54 24 ?? 03 c2 99 b9 ?? ?? ?? ?? f7 f9 8b 4c 24 ?? 8b 44 24 ?? 83 c1 01 89 4c 24 ?? 8a 54 14 ?? 30 54 08}  //weight: 1, accuracy: Low
        $x_1_20 = "OZFaOcht2zWXeAHBECHFBllTAxLopzP1b06grB2Y" ascii //weight: 1
        $x_1_21 = {81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 03 8a 54 14 ?? 32 c2 88 03 04 00 8a 44 34}  //weight: 1, accuracy: Low
        $x_1_22 = "AuYgFhFnVhHYy3y9pnCsqEHQQ7n0BsYZoVjKZmT" ascii //weight: 1
        $x_1_23 = {33 c9 8a 8c 2c ?? ?? ?? ?? 25 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8b 8c 24 ?? ?? ?? ?? 8b b4 24 ?? ?? ?? ?? 8a 04 31 8a 94 14 ?? ?? ?? ?? 32 c2 88 04 31}  //weight: 1, accuracy: Low
        $x_1_24 = "tk0Evb2aWtWmGye0L6WCFIAtE5VEgaJEprg4TmHB3DIOKR" ascii //weight: 1
        $x_1_25 = {0f b6 07 0f b6 cb 03 c1 99 8b ce 83 4d ?? ff f7 f9 8b 45 ?? 8a 8c 15 ?? ?? ?? ?? 30 08}  //weight: 1, accuracy: Low
        $x_1_26 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5d 00 8d 4c 24 ?? 8a 94 14 ?? ?? ?? ?? 32 da 88 5d 00}  //weight: 1, accuracy: Low
        $x_1_27 = "39kSF3VQjV3yuq0mIDkukw75rUizCJZfh6" ascii //weight: 1
        $x_1_28 = {03 c1 8b cf 99 f7 f9 8b 45 ?? 83 4d ?? ff 8a 8c 15 ?? ?? ?? ?? 30 08 04 00 0f b6 4d}  //weight: 1, accuracy: Low
        $x_1_29 = "jbwqRa69kRbNY6RRTRaO1aji0lNzHjSBVfhy7kxm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PBB_2147762605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PBB!MTB"
        threat_id = "2147762605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DllRegisterServer" ascii //weight: 1
        $x_1_2 = "DllUnregisterServer" ascii //weight: 1
        $x_2_3 = "DllUnregisterServerrssssss" ascii //weight: 2
        $x_2_4 = "\\winhlp32.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_PBB_2147762605_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PBB!MTB"
        threat_id = "2147762605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 0f 81 e2 ff 00 00 00 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8a 04 0a 8a 14 2b 32 c2 88 03}  //weight: 1, accuracy: Low
        $x_1_2 = "JeS~~PcCsCq*E{ip?RduQx9yYZwy7r3cT3YUZj~xa71aS6Ykx|eD8M@VtbyH4ON~wQ5vjFXc2pb1k$WLmpi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PBC_2147762728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PBC!MTB"
        threat_id = "2147762728"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 0c 33 0f b6 04 37 03 c1 33 d2 f7 35 ?? ?? ?? ?? 8b 44 24 ?? 8a 0c 28 8b 44 24 ?? 8a 14 32 32 d1 88 55 00}  //weight: 1, accuracy: Low
        $x_1_2 = "nygNeFT}dF8~g4wvh9ye@FMAgNmS94?SkFb7O8eXZnw?3by|j~2LBCNR2EjoMnghG2A~Z}v3GXa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PBD_2147762729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PBD!MTB"
        threat_id = "2147762729"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DllRegisterServer" ascii //weight: 1
        $x_2_2 = {2b d7 03 54 24 ?? 03 54 24 ?? 03 54 24 ?? 0f b6 14 02 8b 44 24 ?? 30 54 28 ?? 3b ac 24 [0-4] 0f 82}  //weight: 2, accuracy: Low
        $x_2_3 = {03 d7 03 54 24 ?? 03 54 24 ?? 0f b6 14 02 8b 44 24 ?? 30 54 28 ?? 3b 6c 24 ?? 0f 82}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_PBD_2147762729_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PBD!MTB"
        threat_id = "2147762729"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 54 24 ?? 0f b6 04 2b 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8a 04 2a 8b 54 24 ?? 32 04 11 8b 54 24 ?? 88 04 11}  //weight: 1, accuracy: Low
        $x_1_2 = "qq62wfTZVc9scve$ridi%NFzJiDkjqi|7mNx{ynlYBZeOJNd~fXm4s|cySonVN@SO0w1~{FC7X1Qkr?b6Zapht" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PBE_2147762804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PBE!MTB"
        threat_id = "2147762804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 99 bd 2c 4d 00 00 f7 fd a1 ?? ?? ?? ?? 8d 04 42 2b c6 2b c1 03 44 24 ?? 8b 54 24 ?? 03 44 24 ?? 03 44 24 ?? 03 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PBE_2147762804_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PBE!MTB"
        threat_id = "2147762804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 08 8b 55 ?? 33 c0 8a 04 0a 8b 4d ?? 03 4d ?? 33 d2 8a 11 33 c2 8b 0d ?? ?? ?? ?? 8b 11 8b 4d ?? 88 04 11}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 04 0b 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8a 04 0a 8b 55 ?? 32 04 17 8b 55 ?? 88 04 17}  //weight: 1, accuracy: Low
        $x_1_3 = "R{w%kfP6s|SHIBxxj7CkBu9Qt{0BwtDlW}t{s6RhR2ro|DQ@qpzmvNSuq?uVK1JT@|krIL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PBF_2147762812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PBF!MTB"
        threat_id = "2147762812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 33 03 c1 f7 35 ?? ?? ?? ?? 8b 44 24 ?? 8a 0c 28 8a 14 32 32 d1 8b 4c 24 ?? 88 14 29}  //weight: 1, accuracy: Low
        $x_1_2 = "$hj%k0GA2?2*I8qSME35%yLhK05FAL1fgYz~p%CB~7cRo84GsaNHRocjh7khXQ3iQ2y|?K#YPqt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PBG_2147762813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PBG!MTB"
        threat_id = "2147762813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 0f 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8a 04 0a 8b 54 24 ?? 32 04 13 8b 54 24 ?? 88 04 13}  //weight: 1, accuracy: Low
        $x_1_2 = "k~e{%bP3~fAB2LCWVCVJszJl@kGJfFH~6F~@3|*0R2%m%e0VDsNTmYAsO~eY9Ag3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PBH_2147762874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PBH!MTB"
        threat_id = "2147762874"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 0e 0f b6 d2 03 c2 33 d2 f7 35 ?? ?? ?? ?? 0f b6 04 0a 8b 54 24 ?? 32 04 13 8b 54 24 ?? 88 04 13}  //weight: 1, accuracy: Low
        $x_1_2 = "b~ebdn~xmahtOGHd5VmGejpn$nf6LiCpoh6gViOE8VzO@CZc5@l$iT1@@CCwPIHAoGCN0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PBI_2147762875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PBI!MTB"
        threat_id = "2147762875"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 0f 81 e2 ff 00 00 00 03 c2 33 d2 f7 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 00 8a 14 0a 32 14 18 a1 ?? ?? ?? ?? 8b 5c 24 ?? 8b 00 88 14 18}  //weight: 1, accuracy: Low
        $x_1_2 = "OAP3omnWMiepSvwaMZ*LQpZZq~JBMCs%Kh8njHs7aMB~TdnXESJ4x%%WcX*AZ3LUVlaYrJe~x%os5CYcWMl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PBK_2147762945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PBK!MTB"
        threat_id = "2147762945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 0a 8b 0d ?? ?? ?? ?? 8b 11 8b 4d ?? 0f b6 14 11 33 c2 8b 0d ?? ?? ?? ?? 8b 11 8b 4d ?? 88 04 11}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 14 0a 8b 00 32 14 18 a1 ?? ?? ?? ?? 8b 5c 24 ?? 8b 00 88 14 18 a1 ?? ?? ?? ?? 40 3b c5 a3 ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_3 = "igCaLBQ~j{@ojz2#V9q|*36wp$1gfuP7ELqM@2?j8A2QPaGU*YRz~ZyHA6DwAEV9y5dzn0LPMSeDS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PBL_2147762953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PBL!MTB"
        threat_id = "2147762953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 0a 8b 0d ?? ?? ?? ?? 8b 11 8b 4d ?? 33 db 8a 1c 11 33 c3 8b 15 ?? ?? ?? ?? 8b 0a 8b 55 ?? 88 04 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "@v%F4TWFR9QlRJhvzcP#p1Kf9!KPynRlYf%cWKdU8Ew@IZd" ascii //weight: 1
        $x_1_3 = "KW~vmI8BQF%pK@KstzN~Y07YwCb3ZD{H?QXc1DL35fN@joR9sNVU6Mlpn5D%cJh~@6VX1qE2}ip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PBM_2147763030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PBM!MTB"
        threat_id = "2147763030"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 01 0f b6 ca 03 c1 25 ?? ?? ?? ?? 79 ?? 48 0d 00 ff ff ff 40 8a 84 05 ?? ?? ?? ?? 32 04 37 88 06}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 04 0a 8b 4d ?? 8b 11 8b 4d ?? 33 db 8a 1c 11 33 c3 8b 15 ?? ?? ?? ?? 8b 0a 8b 55 ?? 88 04 0a}  //weight: 1, accuracy: Low
        $x_1_3 = "bMgBo2S1*Ki}V~5n28Si#20f~}M4KZ?dy%@nCMnTQJLc*E4bJ|$A8DSZne4pTXEJ%@PfX3mKBgvXa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PBN_2147763120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PBN!MTB"
        threat_id = "2147763120"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 33 d2 f7 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 00 8b ea 8b 54 24 ?? 8a 14 10 32 14 2e 8b 6c 24 ?? 88 14 28 a1 ?? ?? ?? ?? 40 3b c3 a3}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 14 01 8b 45 ?? 8b 08 8b 45 ?? 33 db 8a 1c 08 33 d3 8b 0d ?? ?? ?? ?? 8b 01 8b 4d ?? 88 14 01}  //weight: 1, accuracy: Low
        $x_1_3 = "bx4qcITOI3MZ{yqQF45#g#$?FQURwmRJ%s@POc@cNedTDB0lBfjqNp1tH~B~udqvk9PFV{|45@j" ascii //weight: 1
        $x_1_4 = "%F}7~R9RdcMUkAc{U*Mzcn#F~U}e%#nVFwu~ziohe9qu$}#pyMXQt*PE1*MIsD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PBO_2147763454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PBO!MTB"
        threat_id = "2147763454"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 11 03 c2 33 d2 f7 35 ?? ?? ?? ?? 89 55 ?? 8b 45 ?? 03 45 ?? 0f b6 08 8b 55 ?? 03 55 ?? 0f b6 02 33 c8 8b 55 ?? 03 55 ?? 88 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "6Z6x8!4zpUCX@R#toJr^+TCgAUZ(Q%ylNN>>FTZD_XQd$eGdqe@v?1J48XWg!*)(O9tF@RENQV27J_nbjWhEt%U5@&RL(^C?NZe>&SRx1xAVYzU6ZpO^Q" ascii //weight: 1
        $x_1_3 = "j?RU(^Ku(7sKk%fqoQELyH1Z)^!pzQUZH(Q>%MV!190*ac<doCca4Y?(LcO>ygTQm2p)C1w#vaQqHuMirbagWJ@?FukWEf$3txfeXl!WHTiwbGfYg4xm2" ascii //weight: 1
        $x_1_4 = ")t2>1coooLM$^!WGbEas76FFNah)Cvzg1Cs&zeN^UgII5S!ZB9OYQ" ascii //weight: 1
        $x_1_5 = "H3BWp#n&65q<O@CH+DAm@I^Rcg%V(Jt6K+IGx_BhF2blc838KHk2^Pipsx" ascii //weight: 1
        $x_1_6 = "V6Guu#fuHY$RQD+9GJyZ<CgtOkpjM#(aQAKKp?Sv9A5#DwK>y2&))__v+N%Tp%g%n?y^xxhq8539vQk1V&1%!5sc5$ST#+Ud(d%e" ascii //weight: 1
        $x_1_7 = "iHc%jZd29c5nx54iuDeY*O_z^<z3bV6LavP&J+G<8oDWpA*37?GNLvMYvWm(!w+9nTXqAxcW53XoSPgxKHDyy)RSl4?VADR<)nqA)7Ile*SzE84@WSy*vXbZ" ascii //weight: 1
        $x_1_8 = "%XlhDZVgegNOSkGe$AFkf{cdHY$B7Oe{atCVWoKDk}8W5|20aHI~v}SF6~Cjv$UVMq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_PBP_2147763455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PBP!MTB"
        threat_id = "2147763455"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 0c 37 0f b6 04 30 03 c1 83 4d ?? ff f7 35 ?? ?? ?? ?? 8b 45 ?? 8d 8d [0-4] 8a 04 18 32 04 32 88 03}  //weight: 1, accuracy: Low
        $x_1_2 = "rRXK34FT~Oi?8}dfe2s3r0w$SP5EXn1TS9zSWz@VumtCe{?eirfhMn|Dzfp~QVvGlcV{U6fZhW0WN" ascii //weight: 1
        $x_1_3 = "O8#9u0VJIUe?X04(VY3i9$&tGBuVwuIzN!HM40Thii$305<CfBjZQrfhKayoSrgScUWL$d3p0hPUM$#YHstO1nzJN0zL2pDEYcz0W8G" ascii //weight: 1
        $x_1_4 = "DVQ#fry1zXzoous%*?msb$??9OJoOZpdLYgq%2wsAlNsDpT9WglS|JlupE1brbm3rzY}O7LxH*cTXtqMZ5E" ascii //weight: 1
        $x_1_5 = "wdH4vRarWzK%jt6EPEKM~R?oRHbuXuRCkH%HBcn~CPjP~uhxaZMGOlW|e3gXa1bIN|?5#" ascii //weight: 1
        $x_1_6 = "?QWYgYUs5o#qk<l!))kbHZ_s!Y@f6?tJs&Aib#xJWI" ascii //weight: 1
        $x_1_7 = "hVp&LphxXM(*n28%s&#*8T^+1<ZV2Wj&W07G%?&SlshDx&NTS$y&WRxGLkgU*gwQ5JL@nT$ovn7dHGpk" ascii //weight: 1
        $x_1_8 = "V)cRjmC%*8iWFN@Z_kesf0samys+AkaEdxwO!PY0?r82xqm3r#$>>5WCyM)9LPvyPKDC<xQO6gcUN%r(#9QyVF9vN&?TH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_SA_2147763469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SA!MTB"
        threat_id = "2147763469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 24 8a d0 02 d0 c0 e8 07 32 d0 80 c2 37 8a ca c0 e9 04 c0 e2 04 8b 74 24 04 0a ca 80 c1 3d 88 0c 24 8a 1c 75 08 e0 02 10 8d 7e 01 0f b7 c7 32 d9 88 5c 34 20 89 44 24 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RAC_2147766117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RAC!MSR"
        threat_id = "2147766117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 c2 99 bb ?? ?? ?? ?? f7 fb 45 0f b6 c2 8a 0c 08 8b 44 24 ?? 30 4c 28 ?? 3b 6c 24 ?? 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PAD_2147766197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PAD!MTB"
        threat_id = "2147766197"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {66 0f b6 1a 8b cf 66 d3 e3 42 66 f7 d3 0f b7 cb 8b d9 c1 eb 08 88 18 88 48 01 03 c6 ff 8d}  //weight: 5, accuracy: High
        $x_5_2 = {42 45 41 55 52 45 47 41 52 44 5c 50 69 63 74 75 72 65 73 5c [0-16] 5c 57 6f 72 6b 65 72 54 68 72 65 61 64 73 5c [0-21] 5c 57 6f 72 6b 65 72 54 68 72 65 61 64 73 2e 70 64 62}  //weight: 5, accuracy: Low
        $x_1_3 = "LockWindowUpdate" ascii //weight: 1
        $x_1_4 = "NoNetConnectDisconnect" ascii //weight: 1
        $x_1_5 = "RecentDocsHistory" ascii //weight: 1
        $x_1_6 = "LockFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PAE_2147771634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PAE!MTB"
        threat_id = "2147771634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "63[4]5mm]5\\]m]mm5\\mm5555555\\\\\\5\\\\\\5m\\55\\\\5ed" ascii //weight: 1
        $x_1_2 = "cOXY/P.Z0.0.QR00/ZPP0000000/0PPZR.BI@/DE0" ascii //weight: 1
        $x_3_3 = {03 c2 99 f7 fb 0f b6 c2 0f b6 14 08 30 55 ?? 83 6c 24 ?? 01 75 ?? 8a 4c 24 ?? 8b 44 24 ?? 8a 54 24 ?? 5f 5e 5d 88 50 01 88 08 5b 83 c4 ?? c3}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PAG_2147771687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PAG!MTB"
        threat_id = "2147771687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 0f b6 04 08 0f b6 0c 0a 33 d2 03 c1 b9 [0-4] f7 f1 8a da ff ?? 6a 00 6a 00 ff ?? a1 ?? ?? ?? ?? 8b f7 2b 35 ?? ?? ?? ?? 0f b6 cb 8a 04 01 8b 4d ?? 30 04 0e 47 be ?? ?? ?? ?? 8b 4d ?? 3b 7d ?? 0f 8c ?? ?? ?? ?? 8b 7d ?? 8a 45 ?? 5e 88 3f 88 47 ?? 5f 5b c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PAG_2147771687_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PAG!MTB"
        threat_id = "2147771687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 0a 8b 01 8b 40 ?? ff d0 0f b6 c0 8b ce 50 e8 [0-4] 8b ce e8 [0-4] a1 [0-4] 8b d7 0f b6 [0-4] 47 2b 15 [0-4] 8a 04 01 b9 ?? ?? 00 00 30 04 1a 8b 45 ?? 3b 7d ?? 0f 8c}  //weight: 2, accuracy: Low
        $x_1_2 = "Xbl@YcmAZdnB[eoC\\fpD]gq" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PAH_2147771778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PAH!MTB"
        threat_id = "2147771778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 59 0f b6 0c 10 8b 45 ?? 0f b6 04 10 03 c8 81 e1 ?? ?? ?? ?? 79 ?? 49 83 c9 ?? 41 0f b6 c1 8b 4d ?? 8a 04 10 30 04 0e 47 8b 45 ?? 8b 55 ?? 3b 7d ?? 0f 8c ?? ?? ?? ?? 8b 7d ?? 8b 45 ?? 5e 88 5f ?? 88 07 5f 5b 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PAH_2147771778_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PAH!MTB"
        threat_id = "2147771778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 50 e8 ?? ?? ?? ?? 8b 4c 24 ?? 8b 44 24 ?? 8b 35 ?? ?? ?? ?? 8b d1 2b 15 ?? ?? ?? ?? 41 03 c2 0f b6 54 ?? ?? 8a 14 32 30 10 3b 4c 24 ?? 89 4c 24 ?? 0f 8c ?? ?? ?? ?? 8a 4c 24 ?? 8b 44 ?? 24 8a 54 24 ?? 5f 5e 5d 5b 88 50 ?? 88 08 83 c4 08 c3}  //weight: 2, accuracy: Low
        $x_1_2 = {99 f7 fb 8a c2 88 45 ?? 0f b6 c0 89 45 ?? 03 c1 50 57 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {99 f7 f9 0f b6 c2 8a 04 38 30 03 8b 45 ?? 8b 5d ?? 3b 75 ?? 7c [0-4] 8b 75 ?? 8a 45 ?? 5f 5b 88 06 8a 45 ?? 88 46 ?? 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_PAM_2147773370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PAM!MTB"
        threat_id = "2147773370"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 ff 32 c9 33 f6 fe c7 8d [0-5] 0f b6 c7 03 d0 8a 1a 02 cb 0f b6 c1 88 [0-5] 8d [0-5] 03 c8 0f b6 01 88 02 88 19 0f b6 0a 0f b6 c3 03 c8 0f b6 c1 8a [0-5] 0f b6 84 05 [0-5] 30 04 3e 46 81 fe [0-5] 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RT_2147777695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RT!MTB"
        threat_id = "2147777695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 d1 2b d0 8b [0-5] 8a 18 8a 0c 32 32 d9 8b [0-5] 88 18 8b [0-5] 40 3b c1 89 [0-5] 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RT_2147777695_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RT!MTB"
        threat_id = "2147777695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 0f b6 44 24 ?? 57 99 bf ab 05 00 00 f7 ff 80 c2 3d 85 f6 76 ?? 8a 01 32 c2 02 c2 88 01 41 83 ee 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RT_2147777695_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RT!MTB"
        threat_id = "2147777695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 00 00 f7 fb 8b 44 24 ?? 8a 04 08 41 81 f9 ?? 69 00 00 8a 1c 17 88 5c 0e ?? 88 04 2a 7c}  //weight: 1, accuracy: Low
        $x_1_2 = "Vi@BZV&*Krh9hF^Qd!iipdj1%#vd@HZv3GEbO0Tnct?sQWWfb%bkr2eO1Y8u!gb(XS6kIhtQebRxD)L!ZQUVMaZV^fZ_09MF&" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RT_2147777695_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RT!MTB"
        threat_id = "2147777695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "VVrSRIMl60oWDptBZzgQopLVdg3iyp26gCVgvztlIm5D70GL9aF3m7TlYwYWBjTts83Hzut2wCAGFKPNdocm98G3Wf5eR7" ascii //weight: 10
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
        $x_1_3 = "GetStringTypeW" ascii //weight: 1
        $x_1_4 = "GetCPInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RT_2147777695_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RT!MTB"
        threat_id = "2147777695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "p6Nwk3*A3IcEIKe$J>Iei<?GRd4jyc09YREa@+TY<!e+EXBSEDXnYnwpE<iW%sjVY80C^sc<AQ#wcWuMpbO(tiBUmD^TrN(5b)+trZvqLV5$A*71VZ" ascii //weight: 1
        $x_1_2 = {83 c4 04 f7 d8 50 ff 15 ?? ?? ?? ?? 89 45 ?? eb [0-4] 6a 40 68 00 30 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RT_2147777695_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RT!MTB"
        threat_id = "2147777695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0d 00 10 00 00 50 56 53 6a ff ff 15 ?? ?? ?? ?? eb}  //weight: 10, accuracy: Low
        $x_10_2 = {0b e8 55 57 6a 00 6a ff ff 15 ?? ?? ?? ?? e9}  //weight: 10, accuracy: Low
        $x_1_3 = "1x2LGrjhfg?ol(VJ3qX3pYl4pbhiWOUd$ecw&M4pXn!y2O@A&6&o>O@lDeRG^KfohRU)t#HS%LAMdE^PO^32%*Vga^(*<s^l6FsQ*&wQR7r" ascii //weight: 1
        $x_1_4 = ")2xmg$3%J#gZpE*rmH0*M$%&9*Ta8oU<^z)7G)CI9BA112ZzMhT+ymu6AHI7df1vAzzD3IojvfZwDqXCUyHb<u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_LK_2147784198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.LK!MTB"
        threat_id = "2147784198"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Efpxxlseenn.dll" ascii //weight: 1
        $x_1_2 = "CferpgglDrb" ascii //weight: 1
        $x_1_3 = "Fddppfew.pdb" ascii //weight: 1
        $x_1_4 = "Self ex" ascii //weight: 1
        $x_1_5 = "testapp.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DC_2147799384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DC!MTB"
        threat_id = "2147799384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {83 c4 04 0d 00 10 00 00 50 68 00 4e 02 00 57 6a ff}  //weight: 5, accuracy: High
        $x_5_2 = {83 c4 04 0d 00 10 00 00 50 68 00 4e 02 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DC_2147799384_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DC!MTB"
        threat_id = "2147799384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 e0 2b f2 03 35 ?? ?? ?? ?? 03 35 ?? ?? ?? ?? 8b 45 e4 03 45 0c 8b 4d e8 88 0c 30}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DC_2147799384_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DC!MTB"
        threat_id = "2147799384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {29 c2 89 d0 89 c2 c1 e2 04 01 c2 89 c8 29 d0 01 f8 0f b6 00 31 f0 88 03 83 45 e4 01 8b 45 e4 3b 45 dc 7c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DC_2147799384_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DC!MTB"
        threat_id = "2147799384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ass.DLL" ascii //weight: 1
        $x_1_2 = "ass.ass" ascii //weight: 1
        $x_1_3 = "asdzxcqwe123" ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_6 = "RaiseException" ascii //weight: 1
        $x_1_7 = "Control_RunDLL" ascii //weight: 1
        $x_1_8 = "abziuleoxsborpb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_QW_2147805123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.QW!MTB"
        threat_id = "2147805123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 4c 24 14 8b 44 24 10 33 d2 f7 f1 8b d8 8b 44 24 0c f7 f1 8b d3 eb 41 8b c8 8b 5c 24 14 8b 54 24 10 8b 44 24 0c d1 e9 d1 db d1 ea d1 d8 0b c9 75 f4 f7 f3 8b f0 f7 64 24 18 8b c8 8b 44 24 14 f7 e6 03 d1}  //weight: 10, accuracy: High
        $x_3_2 = "Control_RunDLL" ascii //weight: 3
        $x_3_3 = "hquknivslqkb" ascii //weight: 3
        $x_3_4 = "AppPolicyGetProcessTerminationMethod" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DB_2147805214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DB!MTB"
        threat_id = "2147805214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f7 fd 8b 44 24 68 8b 6c 24 24 83 c5 01 89 6c 24 24 03 54 24 58 03 54 24 5c 03 54 24 60 0f b6 14 02 8b 44 24 38 30 54 28 ff 3b 6c 24 70 0f 82}  //weight: 2, accuracy: High
        $x_2_2 = "DllRegisterServer" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DB_2147805214_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DB!MTB"
        threat_id = "2147805214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 0f 8d 7f 04 33 cb 0f b6 c1 66 89 02 8b c1 c1 e8 08 8d 52 08 0f b6 c0 66 89 42 fa c1 e9 10 0f b6 c1 c1 e9 08 45 66 89 42 fc 0f b6 c1 66 89 42 fe 3b ee 72}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 3c 8b 7c 24 10 89 44 24 30 8b 5c 28 78 03 dd 8b 43 1c 8b 4b 20 03 c5 89 44 24 2c 03 cd 8b 43 24 03 c5 89 4c 24 24 89 44 24 28 eb}  //weight: 1, accuracy: High
        $x_1_3 = "Control_RunDLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RTH_2147805284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RTH!MTB"
        threat_id = "2147805284"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "7kR@X@Buy47X*uZmTX^g5Pe*>G31wAj$Bq_YiSrFJtS614Q)c&" ascii //weight: 1
        $x_1_2 = {0d 00 10 00 00 50 8b 55 b0 52 6a 00 6a ff ff 15 ?? ?? ?? ?? 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RTH_2147805284_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RTH!MTB"
        threat_id = "2147805284"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "d+%7FM8MUeSH0_xH4)LqFl6D^D7wsqk4JxiPq0Vm@$?8mM&SjC<XQ9f7Lt+Kb>SRJQ9" ascii //weight: 1
        $x_1_2 = {2b d1 2b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 8b 4d ?? 0f b6 14 11 8b 4d ?? 0f b6 04 01 33 c2 8b 4d ?? 2b 0d ?? ?? ?? ?? 8b 55 ?? 88 04 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RTH_2147805284_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RTH!MTB"
        threat_id = "2147805284"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "zZ$be(3bR>xg%il7Mr>ujumN8d$eu$j9X^2@Kpj+43BwbSA0&aMek(zuBJ&E)#Zxlf31M(Z9OG?m2>IN9swbhSt&xl^" ascii //weight: 1
        $x_1_2 = {83 c2 01 89 55 ?? 8b ?? ?? 3b ?? ?? 73 [0-18] 03 [0-5] 8a 02 88 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RTH_2147805284_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RTH!MTB"
        threat_id = "2147805284"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "RyumazquDmDbiOjIU5T<0H7RgGNc_mU*z7@@5oXYv&m(RvTLf_sPg!D86B$So3nhTcxiOLWqJ1p0Ub%@&wD#QAWYyUB(ZMaV^yG<5QS^Ggy3kxDb" ascii //weight: 1
        $x_1_2 = {83 c4 04 f7 d8 50 ff 15 ?? ?? ?? ?? 89 45 ?? eb 16 6a 40 68 00 30 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RF_2147805400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RF!MTB"
        threat_id = "2147805400"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "arztoelaoghwuqg" ascii //weight: 1
        $x_1_2 = "bvawnlfmqdqggvri" ascii //weight: 1
        $x_1_3 = "dxbjqqzvgweyxibz" ascii //weight: 1
        $x_1_4 = "ggptlhgkvddpypq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RF_2147805400_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RF!MTB"
        threat_id = "2147805400"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "df?*a3tr7mx6BJrs7<fbT%Y(duJ(MvjR@0dAb5!Qm67)6CKvwUh7OUr0U_rXFhOwT)$kH9qw$U@k" ascii //weight: 1
        $x_1_2 = {83 c5 40 55 68 00 30 00 00 56 53 6a ff ff 15 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RF_2147805400_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RF!MTB"
        threat_id = "2147805400"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "(^tMK&16v4A2HS!$pqKvCS0AW<vnlnjivRSP6mM1eN2SqnGcS)*mZso7MEWLRwkmkI1" ascii //weight: 1
        $x_5_2 = {33 c2 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 8b 75 ?? 2b f2 2b f1 03 35 ?? ?? ?? ?? 03 35 ?? ?? ?? ?? 8b 4d ?? 88 04 31 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RFA_2147805401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RFA!MTB"
        threat_id = "2147805401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "y_fvA2fuV#qhZ0tas>i@?Audict*xl_G(GwW%XMIv87I+<tCDcKOB*vsl" ascii //weight: 1
        $x_1_2 = "a_BY$a$5^0ilcp6!kHgBSXQK5S7_%Vb)aCoO9ZC4Veq8NhEKtP7@WBOO(TEZT?^k6lb^RLBQu)!AT)Fl@*TGa$h+Ip" ascii //weight: 1
        $x_5_3 = {88 14 08 e9 46 00 [0-32] 33 d1 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 4d ?? 2b 0d ?? ?? ?? ?? 2b c8 2b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 8b 45}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_CQ_2147805840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CQ!MTB"
        threat_id = "2147805840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 d8 ba 93 24 49 92 43 d1 e8 f7 e2 c1 ea 02 6b c2 f2 8b 56 08 0f b6 04 01 41 30 84 3a 00 34 02 00 47 75 dc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DI_2147806168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DI!MTB"
        threat_id = "2147806168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 0f 8d 7f 04 33 cb 0f b6 c1 66 89 02 8b c1 c1 e8 08 8d 52 08 0f b6 c0 66 89 42 fa c1 e9 10 0f b6 c1 c1 e9 08 45 66 89 42 fc 0f b6 c1 66 89 42 fe 3b ee 72}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 3c 8b 5c 24 10 89 44 24 28 8b 7c 28 78 03 fd 8b 47 1c 8b 4f 20 03 c5 89 44 24 24 03 cd 8b 47 24 03 c5 89 4c 24 1c 89 44 24 20 eb}  //weight: 1, accuracy: High
        $x_1_3 = "Control_RunDLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_2147807390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.ffhh!MTB"
        threat_id = "2147807390"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "ffhh: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kaod3r3y08cb0qx9lloha8h46a" ascii //weight: 1
        $x_1_2 = "d8hia1wys7lppa3s50lojt" ascii //weight: 1
        $x_1_3 = "ski9xoale4edpc3a6dx" ascii //weight: 1
        $x_1_4 = "wgrnteo3iujx" ascii //weight: 1
        $x_1_5 = "l472azkapoxt" ascii //weight: 1
        $x_1_6 = "wq9om10n281h" ascii //weight: 1
        $x_1_7 = "fvlffvbkbdo69" ascii //weight: 1
        $x_1_8 = "ey79n4y9wg0awowjda00wqrmh6pt9g8" ascii //weight: 1
        $x_1_9 = "xgxd975rxajns9bzhpfzaavrupf" ascii //weight: 1
        $x_1_10 = "c8a2jkz7bq557c5f8mzzzgodexo73y" ascii //weight: 1
        $x_1_11 = "z4qzdlpedgaps2rbb1dlw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_QE_2147807484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.QE!MTB"
        threat_id = "2147807484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "kejfwuhiegjwhgwuhi4hheyyfiwgh.txt" ascii //weight: 3
        $x_3_2 = "Erica 25 Berlin" ascii //weight: 3
        $x_3_3 = "dll32smpl.pdb" ascii //weight: 3
        $x_3_4 = "Btowctrans" ascii //weight: 3
        $x_3_5 = "IsProcessorFeaturePresent" ascii //weight: 3
        $x_3_6 = "GetSystemTimeAsFileTime" ascii //weight: 3
        $x_3_7 = "LockResource" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_ZZ_2147807911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.ZZ"
        threat_id = "2147807911"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {8b c8 8b d6 d3 e2 8b c6 8b cd d3 e0 03 d0 0f be c3 03 d0 8b 44 ?? ?? 2b d6 47 8b f2 8a 1f 84 db 75 de}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_ZY_2147807912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.ZY"
        threat_id = "2147807912"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_5_2 = {0f be 03 89}  //weight: 5, accuracy: High
        $x_5_3 = {d3 e2 01 55 ?? 29}  //weight: 5, accuracy: Low
        $x_5_4 = {80 3b 00 75}  //weight: 5, accuracy: High
        $x_5_5 = {0f b7 04 78 8b 34 86 03 f5 3b f3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GLM_2147807961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GLM!MTB"
        threat_id = "2147807961"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 15 04 84 40 00 31 c0 0b 05 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 8b 00 01 05 04 84 40 00 8d 1d 04 84 40 00 81 2b 9f 00 00 00 72 42 ff 33 5b 83 7d fc 00 75 02 74 11 8d 05 83 51 a8 55 01 05 1c 84 40 00 e8 ?? ?? ?? ?? 8d 0d 41 4f a8 55 31 c0 ff b0 1c 84 40 00 58 01 c1 89 0d 1c 84 40 00 eb 00 a1 1c 84 40 00 50 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PW_2147808178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PW!MTB"
        threat_id = "2147808178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 18 66 03 10 c3 b8 20 66 03 10 c3 e8 [0-4] 8b 48 ?? 83 08 ?? 89 48 ?? e8 [0-4] 8b 48 ?? 83 08 02 89 48 ?? c3 b8 d8 6c 03 10 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RW_2147810004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RW!MTB"
        threat_id = "2147810004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 04 0f af 05 ?? ?? ?? ?? 03 d0 8d 47 ?? 0f af c7 2b d0 8b 44 24 ?? 2b d3 2b d1 8a 0c 32 30 08 8b 44 24 ?? 40 89 44 24 ?? 3b 44 24 ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RW_2147810004_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RW!MTB"
        threat_id = "2147810004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "_#i@YR!I_pD1VPRZ3yi$PT<4y$iI#y9#t8)XA4P9" ascii //weight: 1
        $x_1_2 = {83 c4 04 f7 d8 50 ff 15 ?? ?? ?? ?? 89 45 ?? eb ?? 6a 40 68 00 30 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RW_2147810004_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RW!MTB"
        threat_id = "2147810004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "^5#CasV0$4&NGbETKS$5?3Q5EIJBxtugk5jHySSSg1cE89ta<KxQqp2kPKrFq2VVzlA$dy2wgw9zu2xb<&jJ" ascii //weight: 1
        $x_1_2 = {0b e9 55 57 6a 00 6a ff ff 15 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RTA_2147810242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RTA!MTB"
        threat_id = "2147810242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b c9 03 0f af d7 03 d3 03 d0 8b 44 24 ?? 8a 0c 11 30 08 ff 44 24 ?? 8b 44 24 ?? 3b 44 24 ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RTA_2147810242_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RTA!MTB"
        threat_id = "2147810242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bahkgkxkdroklj" ascii //weight: 1
        $x_1_2 = "bkazzsdpctpmyra" ascii //weight: 1
        $x_1_3 = "ewoypwsbdapm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RTA_2147810242_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RTA!MTB"
        threat_id = "2147810242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b c1 50 56 6a 00 6a ff ff 15 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = {03 c5 03 44 24 ?? 8b 6c 24 ?? 03 44 24 ?? 83 c5 01 03 44 24 ?? 89 6c 24 ?? 0f b6 14 10 8b 44 24 ?? 30 54 28 ?? 3b ac 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RTA_2147810242_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RTA!MTB"
        threat_id = "2147810242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 0b c8 51 8b 45 ?? 50 6a 00 6a ff ff 15 ?? ?? ?? ?? 89 45 ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = "OQZXMJdBz1G+o@d+c#z8OAHX$(1*S70o37VIDuvo$>PT1)vpe)thl@nrAGZxGtLAseBYmh7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_EI_2147810551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.EI!MTB"
        threat_id = "2147810551"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 16 8d 49 04 33 55 08 8d 76 04 88 51 fc 8b c2 c1 e8 08 47 c1 ea 10 88 41 fd 88 51 fe c1 ea 08 88 51 ff 3b fb 72}  //weight: 10, accuracy: High
        $x_1_2 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_3 = "RaiseException" ascii //weight: 1
        $x_1_4 = "CreateFileW" ascii //weight: 1
        $x_1_5 = "CreateFileMappingW" ascii //weight: 1
        $x_1_6 = "MapViewOfFile" ascii //weight: 1
        $x_1_7 = "GetFileSize" ascii //weight: 1
        $x_1_8 = "WriteFile" ascii //weight: 1
        $x_1_9 = "UnmapViewOfFile" ascii //weight: 1
        $x_1_10 = "CloseHandle" ascii //weight: 1
        $x_1_11 = "CreateProcessW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_RPG_2147810701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RPG!MTB"
        threat_id = "2147810701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c8 8b 55 e0 2b ca 8b 45 e4 2b c8 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 8b 55 0c 8b 45 e8 88 04 0a e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RPH_2147810702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RPH!MTB"
        threat_id = "2147810702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ab ab ab ab 8b 7d bc b9 14 00 00 00 b8 44 00 00 00 57 ab 33 c0 ab e2 fd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RPI_2147810703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RPI!MTB"
        threat_id = "2147810703"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {9c 3f 61 f0 27 96 82 6b 5d 26 33 21 b8 5b ce 4e 9c 5e 38 72 42}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DM_2147810744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DM!MTB"
        threat_id = "2147810744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 14 0a 03 c2 33 d2 bd ?? ?? ?? ?? f7 f5 8b 6c 24 40 03 d3 8a 04 2a 30 07}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DG_2147810886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DG!MTB"
        threat_id = "2147810886"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "JIONd3ka@>BrT^zSFleDgx4GG" ascii //weight: 3
        $x_3_2 = "GetTempFileNameA" ascii //weight: 3
        $x_3_3 = "GetTempPathA" ascii //weight: 3
        $x_3_4 = "DeleteFileA" ascii //weight: 3
        $x_3_5 = "\\shell\\open\\" ascii //weight: 3
        $x_3_6 = "DllRegisterServer" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DE_2147810946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DE!MTB"
        threat_id = "2147810946"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {f7 f1 83 c6 01 8b ca 8b 54 24 14 8a 44 32 ff 8b d1 2b d3 0f b6 14 3a 88 54 2e ff}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DE_2147810946_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DE!MTB"
        threat_id = "2147810946"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {85 ff 74 27 29 c9 49 23 0a 83 c2 04 83 c1 ee 31 d9 8d 49 ff 89 cb 89 4e 00 83 ef 04 83 ee fc c7 05 [0-4] 07 1a 40 00 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DN_2147811143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DN!MTB"
        threat_id = "2147811143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {f7 f5 8b 44 24 40 8b 6c 24 1c 2b d3 03 d7 8a 04 02 30 45}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_DR_2147811144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.DR!MTB"
        threat_id = "2147811144"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 6c 24 40 8b 44 24 14 2b d3 03 d5 8b 6c 24 48 8a 14 2a 30 14 38}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CR_2147811254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CR!MTB"
        threat_id = "2147811254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 44 24 44 03 d5 03 d3 8a 14 02 8b 44 24 3c 30 14 38}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GTM_2147811347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GTM!MTB"
        threat_id = "2147811347"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 fc 89 45 f0 eb 12 8b 4d f4 83 c1 01 89 4d f4 8b 55 f0 83 c2 01 89 55 f0 81 7d f4 00 e1 f5 05 73 0a 8b 45 f0 8a 4d f4 88 08 eb db}  //weight: 10, accuracy: High
        $x_1_2 = "c:\\temp\\~emptydoc.vxml" ascii //weight: 1
        $x_1_3 = "http://madebits.com/" ascii //weight: 1
        $x_1_4 = "katala.dll" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
        $x_1_6 = "ShellExecute" ascii //weight: 1
        $x_1_7 = "GAIsProcessorFeaturePresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_MA_2147811565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.MA!MTB"
        threat_id = "2147811565"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 f4 83 c2 01 89 55 f4 8b 45 f4 3b 45 10 73 ?? 8b 4d fc 03 4d f4 8b 55 f8 03 55 f4 8a 02 88 01 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d ec 8b 55 f0 03 51 0c 89 55 f8 8b 45 ec 8b 48 10 51 8b 55 ec 8b 45 08 03 42 14 50 8b 4d f8 51 e8 ?? ?? ?? ?? 83 c4 0c 8b 55 ec 8b 45 f8 89 42 08 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_ADA_2147811661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.ADA!MTB"
        threat_id = "2147811661"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 57 8b 7d ?? 33 d2 c7 45 ?? ?? ?? ?? 00 8b 45 ?? f7 f1 6a 11 89 45}  //weight: 1, accuracy: Low
        $x_1_2 = {80 3b 00 75 ?? 5f 5e 8b 45 ?? 5b 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_3 = {80 3b 00 75 ?? 5f 8b 45 ?? 5e 5b 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_4 = {0f be 03 89 45 ?? 01 75 ?? d3 e2 01 55 ?? 29 7d ?? 43}  //weight: 1, accuracy: Low
        $x_1_5 = {d3 e6 8a 4d ?? 8b 55 50 00 8a 4d ?? 8b 75 [0-80] 81 75}  //weight: 1, accuracy: Low
        $x_1_6 = {80 3b 00 74 [0-4] 57 8b 7d ?? 33 d2 c7 45 ?? ?? ?? ?? ?? 8b 45 f8 f7 f1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Emotet_GF_2147811764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GF!MTB"
        threat_id = "2147811764"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b c1 8b 4d ?? 0f b6 04 01 8b 4d ?? 0f b6 14 11 33 d0 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 75 ?? 2b 35 ?? ?? ?? ?? 03 35 ?? ?? ?? ?? 03 35 ?? ?? ?? ?? 2b 35 ?? ?? ?? ?? 2b f1 2b 35}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RTB_2147812228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RTB!MTB"
        threat_id = "2147812228"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pbztfze6xf4nvmc0ecfhgsx5p3" ascii //weight: 1
        $x_1_2 = "yooai0wjx2ubrrbn5vmb43qzb5qp" ascii //weight: 1
        $x_1_3 = "rc9tvpcps2x4dcyqegzxbncqeh1o" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GH_2147812619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GH!MTB"
        threat_id = "2147812619"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 0c 0a 03 c1 b9 c1 3a 00 00 99 f7 f9 8b 4d ?? 2b 55 ?? 03 55 ?? 8a 04 32 8b 55 ?? 30 04 0a 41 3b 4d ?? 89 4d ?? b9 c1 3a 00 00 72}  //weight: 10, accuracy: Low
        $x_10_2 = "YwaW)Ce*EfOSlNtIc3__wOJYZ%V$MzT%uXXRU2o6_A<AquF5Dt<9Rr8_0m" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_RWA_2147813426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RWA!MTB"
        threat_id = "2147813426"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 c7 00 10 00 00 0b c7 50 56 53 6a ff}  //weight: 1, accuracy: High
        $x_1_2 = "QkPuX0n6!T&gM7gD2@wDpptOJG&X_M_IB&?qk)b&9Sq2)zqZPJKh6ca$cKCb&N+" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RWA_2147813426_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RWA!MTB"
        threat_id = "2147813426"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "xKTSN#^CKEoj>9tb#1<*MWTsv634k5bTRC7#e5)NjOXu6FCfwl@JBLpT0>VJx<yPUsA0KzNzEo90c%kT&G4A#MS4&" ascii //weight: 1
        $x_1_2 = {0d 00 10 00 00 [0-5] 8b 55 [0-5] 6a 00 6a ff ff [0-5] 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RWB_2147813749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RWB!MTB"
        threat_id = "2147813749"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DllRegisterServer" ascii //weight: 1
        $x_1_2 = "DllUnregisterServer" ascii //weight: 1
        $x_1_3 = "fiscally" ascii //weight: 1
        $x_1_4 = "aponeurosis" ascii //weight: 1
        $x_1_5 = "delphinic" ascii //weight: 1
        $x_1_6 = "pampangan" ascii //weight: 1
        $x_1_7 = "perjured" ascii //weight: 1
        $x_1_8 = "sedimentate" ascii //weight: 1
        $x_1_9 = "spinsterism" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AF_2147813842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AF!MTB"
        threat_id = "2147813842"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 4c 24 08 75 09 8b 44 24 04 a3 ?? ?? ?? ?? 33 c0 40 c2 0c 00 55 8b ec 83 ec 1c ff 75}  //weight: 1, accuracy: Low
        $x_1_2 = {81 75 f8 ec 93 47 0f 81 45 f8 db 9c 00 00 81 75 f8 be ba 44 0f 83 3c b5 ?? ?? ?? ?? 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AG_2147813936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AG!MTB"
        threat_id = "2147813936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 8b 44 24 ?? 03 ce 03 da 8d 0c 49 03 c9 2b d9 8d 14 fd ?? ?? ?? ?? 2b da 0f b6 0c 2b 30 08 8b 44 24 ?? 40 89 44 24 ?? 3b 44 24 ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = "O03*X4rMFJ1WkzRYfT8k>35yO)!>y%0Rtmwo@ftmd5coxY#&id1uKb%y0@<" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_AH_2147813944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AH!MTB"
        threat_id = "2147813944"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d0 8d 04 bf 2b d0 8b 44 24 ?? 03 d1 8b 0d ?? ?? ?? ?? 0f b6 14 8a 30 10 8b 44 24 ?? 40 89 44 24 ?? 3b 44 24 ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = "tE&8a(>$ifi9<ir&n+3GKiH2TYo$wkRmR9DpBPZuMn7AikGA$t?qLA_L7NZZx#Mq5+$rF6A" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_AH_2147813944_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AH!MTB"
        threat_id = "2147813944"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "f98q9%P$DadFu)V2gYj#ylXP?q$2ZZwY@Bj5OU" ascii //weight: 5
        $x_1_2 = "mbmabptebkjcdlgtjmskjwtsdhjbmkmwtrak" ascii //weight: 1
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_1_4 = "DisableThreadLibraryCalls" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_EC_2147814209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.EC!MTB"
        threat_id = "2147814209"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8d 5c 5b 07 0f af da 8b d7 2b d0 03 d2 03 d2 2b d3 8b 5c 24 1c 0f af de 03 d6 8d 54 95 00 8d 1c 5b 03 db 03 db bd 10 00 00 00 2b eb 8b 5c 24 10 0f af e9 03 d5 03 53 20}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_EC_2147814209_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.EC!MTB"
        threat_id = "2147814209"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rftheairsubdue.VDds" wide //weight: 1
        $x_1_2 = "Himageappear" wide //weight: 1
        $x_1_3 = "movingcZlifevoiddarkness5" wide //weight: 1
        $x_1_4 = "itgreatcreepingtree.lcreepeth" wide //weight: 1
        $x_1_5 = "Testapp.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PY_2147814390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PY!MTB"
        threat_id = "2147814390"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 ae 22 00 00 f7 f9 8d 04 3f 2b d6 03 d5 03 d0 8b 44 24 ?? 8a 0c 02 8b 44 24 ?? 30 08 ff 44 24 ?? 8b 44 24 ?? 3b 44 24 ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CB_2147814920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CB!MTB"
        threat_id = "2147814920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "5!O*XXn+)ed4<QYidi3PiJNE>KfvR%%5>UNx<5NnRWwn6M$kxl" ascii //weight: 3
        $x_3_2 = "CallNextHookEx" ascii //weight: 3
        $x_3_3 = "SetWindowsHookExA" ascii //weight: 3
        $x_3_4 = "ShellExecuteA" ascii //weight: 3
        $x_3_5 = "PathFindExtensionA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_ABA_2147814947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.ABA!MTB"
        threat_id = "2147814947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {99 bd 4d 2c 00 00 8b cd f7 f9 8b 44 24 3c 2b 54 24 30 03 54 24 34 03 54 24 38 8b ca 0f b6 04 08 03 c6 99 f7 fd 8b 44 24 4c 8a 04 08}  //weight: 2, accuracy: High
        $x_2_2 = {8b 54 24 58 0f b6 14 32 89 44 24 28 8b 44 24 54 0f 42 36 04 08 03 c2 99 bd 4d 2c 00 00 f7 fd 8b 44 24 60 8b 6c 24 28 2b d7 2b 54 24 1c 03 d3 8a 04 02 30 45 00 ff 44 24 10}  //weight: 2, accuracy: High
        $x_4_3 = "5maS7Z0Zx!z6mJy5ff#)@$*3?0qEq3(vABIRqeHB!3CPl4XjCTtXQ_2GkaB>qSb*HOD(@4eLQZf_BNRlpfwg" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotet_RK_2147814956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RK!MTB"
        threat_id = "2147814956"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "KA!cR7RS@ltG2%am@*PxpH%9E%%8xvgVtjOHf+QoqtRYqkUsKNk!rQZSs#S32<aylfTzWC+F*iLw06+0ERL>^WDe#Y2Y+pdr$(jKLF*" ascii //weight: 1
        $x_1_2 = {81 ca 00 10 00 00 52 56 53 6a ff ff 15 ?? ?? ?? ?? eb 0f 6a 40 68 00 30 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_ABB_2147815227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.ABB!MTB"
        threat_id = "2147815227"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ZrV%lg09mh4h@@riltp_TfBCFF5#5R@!Qb#foax!UY)N>ky1MaSpH*V?NjmC8(C34#B8" ascii //weight: 1
        $x_1_2 = "G!f@)4dV&*M<Xjcg*yxtn#*$86pWZ9HU!(VKgLzT0Q4W" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_ABD_2147815245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.ABD!MTB"
        threat_id = "2147815245"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PQ5tm_p7SUhIC9l6?Ph(*cxTVgUYwIvKOh^1YZnX3B1dewb5OQ<L&Ch^ZMs*sNc_lasgt9M&fDktjr>x3+xfV#HW1sb+Qh9Pfs>5j2uABk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_ABE_2147815361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.ABE!MTB"
        threat_id = "2147815361"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TXHgWLSwAeb<axx^5ZGaSU?)q70PLu+qd#p%3s82Q7$!kxcW9#o@VV7TMRUD<vv#lM(Bs9R*lPJmde!iZ6L8Rol#+e?L2P?87_n1Zyqj7h" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_ABE_2147815361_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.ABE!MTB"
        threat_id = "2147815361"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {99 b9 fa 02 00 00 f7 f9 a1 c4 b0 04 10 0f af 05 c4 b0 04 10 2b d0 8b 0d b4 b0 04 10 0f af 0d b4 b0 04 10 03 15 c4 b0 04 10 03 ca 8b 15 c4 b0 04 10 0f af 15 c4 b0 04 10 2b ca a1 b4 b0 04 10 0f af 05 b4 b0}  //weight: 1, accuracy: High
        $x_1_2 = "^Alwe$f6YafqAQ1RFl7cdF7O5p0Dg?vI&t" ascii //weight: 1
        $x_1_3 = {d7 50 f9 8d 31 41 42 33 ae ef 35 9a d5 a6 78 7f 0e 4c 3e c2 be 42 cf bd d0 65 c9 3e 4a 2f 4a 62 e6 fa 76 65 e1 2d c6 47 47 51 ed 1a f1 47 9a f6 45 ea fe 27 5c 0d 33 a7 9f a9 6b f5 48 81 af e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_RMA_2147815363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RMA!MTB"
        threat_id = "2147815363"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b c1 50 56 33 db 53 6a ff ff 15 ?? ?? ?? ?? 8b 6c 24 ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = ">B%lI2(%ap@X^kc>ok)72QDhMPY0v_>_Intfv<HzIPUbR52z0WdJa&X30y?Ce#xS39+LUJd<O5f_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RMA_2147815363_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RMA!MTB"
        threat_id = "2147815363"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "G_U7fR_tN>Q3k0S_dat4P*WY<Js8+)C*!d?v!q!?O_6uVxc15t<>DV%r@7JUfyx2ycbCxK@ldX&C#K)?E<@Yu+6SlK$Ir" ascii //weight: 1
        $x_1_2 = {68 00 30 00 00 8b 45 b0 50 6a 00 6a ff ff 15 ?? ?? ?? ?? 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_ABF_2147815468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.ABF!MTB"
        threat_id = "2147815468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ">thaw5g+xap^jFH4nUlCwij5Z7zxMgIrh2o*Za%Tf?" ascii //weight: 1
        $x_1_2 = {1b de 9d df af c9 72 2e 35 ab 34 9d fd d7 33 60 34 ab 0a b6 4c f2 36 8c 48 58 fa 9d 58 8b d4 6d 98 26 11 d0 12 69 56 73 db dc ba 4f c7 cb 26 61}  //weight: 1, accuracy: High
        $x_1_3 = {ba 3a 04 00 00 66 89 55 8a b8 4c 04 00 00 66 89 45 8c b9 37 04 00 00 66 89 4d 8e ba 47 04 00 00 66 89 55 90 b8 46 04 00 00 66 89 45 92 b9 3b 04 00 00 66 89 4d 94 ba 34 04 00 00 66 89 55 96 b8 51 04 00 00 66 89 45 98 b9 37 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotet_ADB_2147815820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.ADB!MTB"
        threat_id = "2147815820"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 83 c4 ?? ab 33 d2 6a ?? ab 59 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ab}  //weight: 1, accuracy: Low
        $x_1_2 = {6b 45 fc 14 68 ?? ?? ?? ?? 51 89 45 fc 6b 45 fc ?? 89 45 fc 8b 45 fc f7 f1 89 45 fc 81 75 fc ?? ?? ?? ?? 8b 45 fc 8b 45 f4 8b 45 f8 e8 ?? ?? ?? ?? 83 c4 ?? 53 ff 75 ?? 56 ff d0 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RPD_2147815871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RPD!MTB"
        threat_id = "2147815871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 10 2b fe 8a 0c 1f 32 d1 8b 4c 24 4c 88 10 8b 44 24 20 40 3b c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_ADC_2147816194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.ADC!MTB"
        threat_id = "2147816194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "131"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {55 8b ec 83 e4 f8 81 ec a0 00 00 00 53 55 56 c7 44 24 ?? ?? ?? ?? ?? be ?? ?? ?? ?? 8b 5c 24 ?? bd ?? ?? ?? ?? 57 8b 7c 24 ?? c7 44 24}  //weight: 10, accuracy: Low
        $x_10_3 = {8b f0 f7 de 1b f6 81 e6 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? e9}  //weight: 10, accuracy: Low
        $x_10_4 = {83 c4 14 6a 00 ff d0 8b e5 5d}  //weight: 10, accuracy: Low
        $x_50_5 = {53 57 8b f8 8b cd d3 e7 8b d8 8b 4c 24 ?? d3 e0 8b c8 66 83 fa 41 72 ?? 66 83 fa 5a 77}  //weight: 50, accuracy: Low
        $x_50_6 = {0f b7 c2 83 c0 20 eb ?? 0f b7 c2 83 c6 02 2b cb 03 cf 03 c1 0f b7 16 66 85 d2 75 ?? 5f 5b 5e 5d 59 59}  //weight: 50, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_MC_2147816642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.MC!MTB"
        threat_id = "2147816642"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 10 73 ?? 8b 55 08 03 55 fc 0f b6 0a 8b 45 fc 33 d2 f7 75 18 8b 45 14 0f b6 14 10 33 ca 8b 45 0c 03 45 fc 88 08 eb}  //weight: 10, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "DllUnregisterServerMode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_MD_2147816942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.MD!MTB"
        threat_id = "2147816942"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "e*JqAjALm18lA@U@7^ZAV7F4*j" ascii //weight: 10
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "DllUnregisterServerKasl" ascii //weight: 1
        $x_1_4 = "LockResource" ascii //weight: 1
        $x_1_5 = "UnhookWindowsHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PAF_2147819908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PAF!MTB"
        threat_id = "2147819908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b da 03 d9 ff 15 ?? ?? ?? ?? 8a 14 33 8a 44 24 ?? 8b 4c 24 ?? 02 d0 8b 44 24 ?? 32 14 01 88 10 40 89 44 24 ?? ff 4c 24 ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = "drtffDWEUFEUFUWEGFUYBG" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_SAE_2147835991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SAE!MTB"
        threat_id = "2147835991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 11 8b 75 ?? 01 d6 89 45 ?? 89 f0 ?? 8b 75 ?? f7 fe 8b 7d}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 14 16 31 d1 8b 55 ?? 8b 32 8b 55 ?? 88 0c 32 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RPB_2147836242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RPB!MTB"
        threat_id = "2147836242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 d2 4a 23 16 83 c6 04 f7 da 8d 52 d7 83 ea 02 83 c2 01 29 ca 31 c9 29 d1 f7 d9 6a 00 8f 03 01 53 00 83 c3 04 83 c0 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_SAF_2147842569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SAF!MTB"
        threat_id = "2147842569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 f9 81 e1 ?? ?? ?? ?? 8b 7d ?? 8b 75 ?? 8a 1c 37 8b 75 ?? 32 1c 0e 8b 4d ?? 8b 75 ?? 88 1c 31 81 c6 ?? ?? ?? ?? 8b 4d ?? 39 ce 8b 4d ?? 89 75 ?? 89 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RDF_2147846505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RDF!MTB"
        threat_id = "2147846505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 1c 17 8a 7c 0c 4f 80 c7 01 8b 54 24 28 8a 14 32 28 da 8b 7c 24 24 88 14 37 30 df 88 7c 0c 4f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_SL_2147847468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.SL!MTB"
        threat_id = "2147847468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nTter$7" ascii //weight: 1
        $x_1_2 = "WRJERhW@" ascii //weight: 1
        $x_1_3 = "THRE.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_RPX_2147888201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.RPX!MTB"
        threat_id = "2147888201"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 08 6a 00 6a 20 6a 04 6a 00 6a 00 68 00 00 00 40 68 ?? ?? ?? ?? ff d3 8b f0 c7 44 24 0c ff ff ff ff 83 fe ff 74 55 6a 02 6a 00 6a 00 56 ff 15 ?? ?? ?? ?? 8d 54 24 10 6a 00 52 8d 44 24 14 6a 04 50 56 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GMF_2147888589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GMF!MTB"
        threat_id = "2147888589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {d3 e6 89 44 24 0c 8b 44 24 0c 8b c8 c1 e1 05 03 c8 89 4c 24 0c 81 74 24 0c 10 a0 74 d8 0f b6 4c 24 0c 8b 54 24 10 0f be 43 ff 89 44 24 10 01 74 24 10 d3 e2 01 54 24 10 29 7c 24 10}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_GNF_2147894746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.GNF!MTB"
        threat_id = "2147894746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OUccj@Ncr8Nc" ascii //weight: 1
        $x_1_2 = "LH2SbH9Y" ascii //weight: 1
        $x_1_3 = "@.themida" ascii //weight: 1
        $x_1_4 = "Csw27L0" ascii //weight: 1
        $x_1_5 = "OSjdYZc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CCFJ_2147899489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CCFJ!MTB"
        threat_id = "2147899489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 c8 8b 40 ?? 89 45 ?? 8b 45 ?? c1 e0 ?? 03 45 ?? 0f b7 40 ?? 89 45 ?? 8b 45 ?? 33 45 ?? 89 45 ?? 8b 45 ?? 03 45 ?? 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_VAA_2147918527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.VAA!MTB"
        threat_id = "2147918527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {01 f7 89 f8 89 55 b4 99 8b 7d b8 f7 ff 8b 7d f0 81 f7 ba 15 9b 7a 88 4d b3 8b 4d dc 8a 0c 11 88 4d ?? 8b 4d dc 89 55 ac 8b 55 b4 89 5d a8 8a 5d b2 88 1c 11}  //weight: 3, accuracy: Low
        $x_3_2 = {01 f1 21 f9 66 c7 45 ee 1a 6a 8b 75 e4 8b 7d ?? 8a 3c 3e 8b 55 dc 32 3c 0a 8b 4d e0 88 3c 39 8b 4d a8}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_VAV_2147918528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.VAV!MTB"
        threat_id = "2147918528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {01 d1 89 c8 99 f7 fe 8b 4d ?? 8a 3c 11 81 f7 50 27 e3 75 8b 75 c0 88 3c 31 88 1c 11 0f b6 0c 31 8b 75 c4}  //weight: 3, accuracy: Low
        $x_3_2 = {8a 1c 0f 8b 4d e4 8b 75 cc 32 1c 31 8b 4d ec 81 f1 ae 27 e3 75 8b 75 e0 8b 7d cc 88 1c 3e 01 cf 8b 4d ?? 39 cf 8b 4d c0 89 4d d0 89 7d d4 89 55 d8 0f 84 51}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_VAC_2147918553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.VAC!MTB"
        threat_id = "2147918553"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 d8 21 f0 8b 74 24 18 8a 0c 06 8b 44 24 20 8a 2c 38 30 e9 8b 5c 24 1c 88 0c 3b 8b 44 24 14 8d bc 07 97 57 aa d9 c7 44 24 ?? ff ff ff ff c7 44 24 ?? c8 c8 af e4 8b 44 24 0c 89 44 24 34 89 7c 24 38 8b 44 24 04 89 44 24 3c 8b 44 24 30 39 c7 74}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_VAD_2147918554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.VAD!MTB"
        threat_id = "2147918554"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {30 df 8b 54 24 54 8b 44 24 50 89 c6 0f af f2 89 44 24 04 8b 54 24 04 f7 e2 01 f2 01 f2 89 44 24 ?? 89 54 24 ?? 8a 5c 24 33 80 f3 3b 88 5c 24 4f 8b 44 24 48 35 18 d6 70 66 8b 54 24 2c 88 3c 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_VAE_2147918555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.VAE!MTB"
        threat_id = "2147918555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 ca 8b 54 24 08 01 d1 21 f1 8b 74 24 24 8a 0c 0e 8b 54 24 ?? 8b 74 24 2c 32 0c 16 8b 54 24 70 8b 74 24 28 88 0c 16 03 7c 24 70 89 5c 24 4c 89 7c 24 6c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_VAF_2147918684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.VAF!MTB"
        threat_id = "2147918684"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 c8 89 4d a8 31 c9 89 55 ?? 89 ca f7 f7 8b 4d d0 81 f6 11 ac 52 09 8b 7d a4 81 f7 10 ac 52 09 89 4d a0 8b 4d a8 21 f9 8b 7d a0 89 4d 9c}  //weight: 5, accuracy: Low
        $x_5_2 = {8b 45 e4 8b 4d f4 81 f1 2c 25 d7 3e 8b 55 ec 8a 1c 02 8b 75 e8 88 1c 06 01 c8 8b 4d ?? 39 c8 89 45 e4 74}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_MIZ_2147919397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.MIZ!MTB"
        threat_id = "2147919397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 e4 8b 4d ec 8a 14 01 8b 75 f4 81 f6 c3 a7 ec 38 8b 7d e8 88 14 07 01 f0 8b 75 f0 39 f0 89 45 e4 74 d2}  //weight: 5, accuracy: High
        $x_5_2 = {80 f3 27 8b 3d ?? ?? ?? ?? 81 c6 d0 aa 00 e4 89 4d b8 8b 4d c4 39 f1 8b 75 b8 0f 47 f2 2a 1c 37 8b 55 e4 8b 75 c0 02 1c 32 8b 7d bc 2b 7d ec 01 f1 8b 55 e0 88 1c 32}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_MIU_2147919398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.MIU!MTB"
        threat_id = "2147919398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 0c 1e 25 ff 00 00 00 8a 04 02 88 6c 24 5f 30 c8 8b 54 24 40 31 d2 89 54 24 60 8b 54 24 ?? 88 04 1a 01 fb 8b 7c 24 10 89 7c 24 4c 89 5c 24 54 8b 44 24 04 89 44 24 48 8b 44 24 44 39 c3 0f 84 a6}  //weight: 5, accuracy: Low
        $x_5_2 = {89 44 24 34 8b 84 24 a8 00 00 00 35 c9 47 bb 4e 89 44 24 30 8b 44 24 38 88 0c 06 8b 74 24 ?? 89 34 24 89 7c 24 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_MIY_2147919399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.MIY!MTB"
        threat_id = "2147919399"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {29 f7 8a 6c 24 7b 88 8c 24 b7 00 00 00 28 ea 81 f6 fd 23 b6 64 66 c7 84 24 ?? ?? ?? ?? 6a 8a 88 54 04 5b 01 f8 89 84 24 84 00 00 00 bf 63 2f ab 49 8b 5c 24 30 89 44 24 10 89 d8 f7 e7 8b 7c 24 34 69 ff 63 2f ab 49 01 fa 89 84 24 b8 00 00 00}  //weight: 5, accuracy: Low
        $x_5_2 = {28 c8 8a 54 24 6b 88 84 24 ?? ?? ?? ?? 8b 74 24 38 83 c6 14 66 8b 7c 24 4c 66 81 cf 2d 6b 66 89 bc 24 ?? ?? ?? ?? 8b 5c 24 48 83 f3 ff 8a 44 24 7b 89 9c 24 ?? ?? ?? ?? 34 e4 89 74 24 5c 66 c7 84 24 ?? ?? ?? ?? 43 32 38 d0 74}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_MIK_2147919400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.MIK!MTB"
        threat_id = "2147919400"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 f0 01 c8 83 c0 44 8b 4d c8 69 c9 ?? ?? ?? ?? 01 ce 81 c6 ?? ?? ?? ?? 8b 0e 8b 75 b8 33 0e 8b 00 29 da 8b 5d c4 81 f3 db d9 75 15 89 3c 24 89 44 24 04 89 4c 24 08 89 5d b4 89 55 b0 89 4d ac e8}  //weight: 5, accuracy: Low
        $x_3_2 = {89 d7 81 f7 e4 2c 10 4b 31 db b8 e1 20 4f 43 29 d0 19 f3 89 5c 24 ?? 89 44 24 10 8b 44 24 ?? 8b 54 24 10 29 fa 19 f0 89 54 24 04 89 04 24 73}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_MID_2147919401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.MID!MTB"
        threat_id = "2147919401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 4d ec 8b 55 ec 81 f2 42 e4 dc 3e 8b 75 bc 8b 7d bc 8b 5d bc 89 75 ac 66 8b 75 f2 66 81 f6 91 36 89 45 a8 a1 ?? ?? ?? ?? 89 45 a4 8b 45 cc 89 45 a0 8a 45 f1 04 a0 88 45 9f 8b 45 a8}  //weight: 5, accuracy: Low
        $x_4_2 = {21 cf 8b 4d 94 81 f1 43 e4 dc 3e 89 4d 8c 8b 4d a0 89 55 88 8b 55 8c 39 d1 8b 4d 88 0f 47 f9 8a 4d 9f 8b 55 a4 2a 0c 3a 66 8b 7d ?? 8b 55 b4 02 0c 1a 88 4d e7 66 39 f7 0f 85}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_MFF_2147919545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.MFF!MTB"
        threat_id = "2147919545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {29 d1 03 8d ?? ?? ?? ?? 29 f0 8a 5d f3 80 f3 84 89 8d ?? ?? ?? ?? 8b 8d f0 fe ff ff 8b 55 0c 8a 3c 0a 88 bd df fe ff ff 02 9d df fe ff ff 88 9d df fe ff ff 8b 8d f0 fe ff ff 89 85 c4 fe ff ff}  //weight: 4, accuracy: Low
        $x_4_2 = {66 b8 a1 6c 8a 4c 24 4b 80 f1 ff 66 8b 54 24 ?? 88 4c 24 4b 66 29 d0 66 89 44 24 1e 66 8b 44 24 1e 66 8b 54 24 38 66 81 f2 55 ?? 66 39 d0 73}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_CCIM_2147923092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.CCIM!MTB"
        threat_id = "2147923092"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 c6 01 d6 81 c6 ?? ?? ?? ?? 8b 16 69 f1 ?? ?? ?? 00 01 f0 05 ?? ?? ?? ?? 33 10 03 54 24 6c 89 54 24 74 8b 44 24 74}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 16 89 54 24 3c 69 54 24 2c ?? ?? ?? ?? 01 d0 05 b8 00 00 00 8b 00 89 c2 31 ca 8b 74 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_EM_2147927184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.EM!MTB"
        threat_id = "2147927184"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 06 8d 76 04 33 44 24 14 42 89 44 37 fc 3b d3 72 ee}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_PGE_2147943449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.PGE!MTB"
        threat_id = "2147943449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2b d0 89 15 88 7d 45 00 8b 0d 14 54 46 00 81 c1 fc 74 7d 01 89 0d 14 54 46 00 8b 15 10 54 46 00 03 55 ec a1 14 54 46 00 89 82 ef fa ff ff 8b 0d 90 7d 45 00 83 c1 3b 2b 0d 94 7d 45 00 89 4d f0 e9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AHB_2147945648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AHB!MTB"
        threat_id = "2147945648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 4d e8 83 c1 02 89 4d e8 8b 55 e4 83 ea 01 89 55 e4 a1 ?? ?? ?? ?? 83 c0 02 0f b6 4d e4 2b c1 66 a3}  //weight: 3, accuracy: Low
        $x_2_2 = {81 c1 ef 35 01 00 2b 0d ?? ?? ?? ?? 03 4d e8 89 4d e8 8b 55 fc 8b 42 02 89 45 f0 8b 4d 0c 83 c1 3b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BAA_2147949081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BAA!MTB"
        threat_id = "2147949081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 f7 8d 3c 08 33 f7 2b d6 05 ?? ?? ?? ?? 83 6d fc 01 75 ?? 8b 45 08 5f 89 10 89 48 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BAB_2147949976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BAB!MTB"
        threat_id = "2147949976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {c1 ea 05 03 51 04 8b c8 c1 e1 04 03 0b 33 d1 8d 0c 07 33 d1 8d bf ?? ?? ?? ?? 2b f2 83 6d 0c 01}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_BAC_2147952703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.BAC!MTB"
        threat_id = "2147952703"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 f7 8d 3c 02 33 f7 29 31 8b 09 8b 7d 0c 8b f1 c1 e6 04 03 37 8b f9 c1 ef 05 03 3b 03 ca 33 f7 33 f1 8b 4d 08 5f 2b c6 5e 89 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotet_AEM_2147953343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotet.AEM!MTB"
        threat_id = "2147953343"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 04 8b 4c 24 08 81 f1 ?? ?? ?? ?? 89 4c 24 24 8b 4c 24 10 8a 14 01 8b 74 24 0c 88 14 06 83 c0 01 8b 7c 24 14 39 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

