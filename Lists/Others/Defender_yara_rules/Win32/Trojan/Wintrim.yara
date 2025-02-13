rule Trojan_Win32_Wintrim_A_116950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wintrim.gen!A"
        threat_id = "116950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wintrim"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 0a 8b 45 ?? 8b 4d ?? 8d (74|7c) (01|08) 04 6a 40 68 00 10 00 00 6a 10 6a 00 ff 55 ?? 8b d8 (83 63|c7 43 0c 00 00) 66 81 (3e|3f) 4d 5a 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Wintrim_H_119006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wintrim.gen!H"
        threat_id = "119006"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wintrim"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4d 43 76 32 44 4c 4c 2e 64 6c 6c 00 53 74 61 72 74 4d 43 00}  //weight: 2, accuracy: High
        $x_1_2 = {e9 dd 07 00 00 55 8b ec 83 ec 34 8b 45 08 8b 48 08 33 d2 42 53 8b 58 0c 56 8b f2 d3 e6 8b 48 04 8b 00 57 8b fa d3 e7 89 45 d4 03 c8 b8 00 03 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Wintrim_A_121768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wintrim.A"
        threat_id = "121768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wintrim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://security-updater.com/binaries/" ascii //weight: 10
        $x_10_2 = "SOFTWARE\\mc" ascii //weight: 10
        $x_10_3 = "http://66.40.9.246/binaries" ascii //weight: 10
        $x_1_4 = "NaviPromoData:decompress failed." ascii //weight: 1
        $x_1_5 = "BuildPopupTitle" ascii //weight: 1
        $x_1_6 = "OpenPopupAndPersist" ascii //weight: 1
        $x_1_7 = "&Password=EWWWWIC" ascii //weight: 1
        $x_1_8 = "mslagent" ascii //weight: 1
        $x_1_9 = {55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00 47 73 6d 00 53 73 6d 00 66 6e 45 67 6d 63 68 6b 00 73 74 62 67 6e}  //weight: 1, accuracy: High
        $x_1_10 = {2d 75 6e 69 6e 73 74 61 6c 6c 00 6d 79 6d 75 74 73 67 6c 77 6f 72 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Wintrim_I_128177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wintrim.gen!I"
        threat_id = "128177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wintrim"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\WinTrust\\Trust Providers\\Software Publishing\\Trust Database\\0" ascii //weight: 1
        $x_5_2 = "electronic-group" ascii //weight: 5
        $x_5_3 = "UNLIMITED ACCESS TO OUR NETWORK" ascii //weight: 5
        $x_4_4 = "\\Instant Access\\Center\\" ascii //weight: 4
        $x_1_5 = "OpenAccess" ascii //weight: 1
        $x_1_6 = "AutodialDllName32" ascii //weight: 1
        $x_8_7 = "EGDACCESS_ASPI" ascii //weight: 8
        $x_4_8 = "SetFromMajRem" ascii //weight: 4
        $x_4_9 = "SetDialerOfflineMode" ascii //weight: 4
        $x_3_10 = "instant access.exe" ascii //weight: 3
        $x_4_11 = "\\dialerexe.ini" ascii //weight: 4
        $x_4_12 = "NOCREDITCARD" ascii //weight: 4
        $x_3_13 = "Software\\EGDHTML" ascii //weight: 3
        $x_1_14 = "RasGetEntryPropertiesA" ascii //weight: 1
        $x_4_15 = "IA_Action" ascii //weight: 4
        $x_2_16 = "AOL Frame25" ascii //weight: 2
        $x_2_17 = "AOL\\C_AOL 9.0" ascii //weight: 2
        $x_1_18 = "\\status.ini" ascii //weight: 1
        $x_1_19 = "Norwegian-Nynorsk" ascii //weight: 1
        $x_1_20 = "english-trinidad y tobago" ascii //weight: 1
        $x_1_21 = "norwegian-nynorsk" ascii //weight: 1
        $x_4_22 = "{31DDC1FD-CEA3-4837-A6DC-87E67015ADC9}" ascii //weight: 4
        $x_4_23 = "{486E48B5-ABF2-42BB-A327-2679DF3FB822}" ascii //weight: 4
        $x_4_24 = "{C6760A07-A574-4705-B113-7856315922C3}" ascii //weight: 4
        $n_100_25 = "Navilog1" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_4_*) and 7 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_4_*) and 3 of ($x_1_*))) or
            ((4 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_4_*) and 2 of ($x_2_*))) or
            ((4 of ($x_4_*) and 1 of ($x_3_*))) or
            ((5 of ($x_4_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 8 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_5_*) and 4 of ($x_4_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((2 of ($x_5_*) and 3 of ($x_4_*))) or
            ((1 of ($x_8_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_3_*) and 8 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 7 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 2 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_8_*) and 2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_8_*) and 3 of ($x_4_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 6 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 2 of ($x_4_*))) or
            ((1 of ($x_8_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 2 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_8_*) and 2 of ($x_5_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Wintrim_D_128261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wintrim.D"
        threat_id = "128261"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wintrim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {4d 43 76 32 44 4c 4c 2e 64 6c 6c 00 53 74 61 72 74 4d 43}  //weight: 10, accuracy: High
        $x_1_2 = "mymutsglwork" ascii //weight: 1
        $x_1_3 = "CEGComputerInfo::GetComputerID()" ascii //weight: 1
        $x_1_4 = "CEGComputerInfo::GetWinVersion()" ascii //weight: 1
        $x_1_5 = "MC_UPDATE" ascii //weight: 1
        $x_1_6 = "Software\\mc" ascii //weight: 1
        $x_1_7 = "NavTime is over." ascii //weight: 1
        $x_1_8 = "RemoteDownloadFile error" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Wintrim_F_139210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wintrim.F"
        threat_id = "139210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wintrim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4d 43 76 32 44 4c 4c 2e 64 6c 6c 00 53 74 61 72 74 4d 43}  //weight: 10, accuracy: High
        $x_5_2 = {45 58 43 45 50 54 49 4f 4e [0-10] 41 43 4b 4e 4f 57 4c 45 44 [0-16] 5f 4c 49 53 54 53 [0-50] 3c 49 44 [0-7] 61 63 6b 6e 6f 77}  //weight: 5, accuracy: Low
        $x_5_3 = {65 6e 63 6f 64 69 6e 67 [0-10] 38 38 35 39 [0-34] 43 6f 6d 70 [0-14] 49 6e 73 74 61}  //weight: 5, accuracy: Low
        $x_5_4 = {6d 41 6e 64 4c 6f 61 64 [0-37] 3a 3a [0-65] 70 6d 63}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Wintrim_G_139256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wintrim.G"
        threat_id = "139256"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wintrim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 79 6d 75 74 73 67 6c 77 6f 72 6b 00 00 00 00 37 30 44 41 36 43 31 37 41 37 34 39 34 43 31 33}  //weight: 1, accuracy: High
        $x_1_2 = {72 72 6f 72 3d 00 00 00 26 6c 61 73 74 65 72 72 6f 72 3d 00 26 61 64 6d 69 6e 3d 00 26 6f 73 69}  //weight: 1, accuracy: High
        $x_1_3 = {46 32 5f 00 38 37 34 39 34 61 30 62 61 38 66 38 66 39 34 65 66 64 37 64 65 62 63 61 66 39 31 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

