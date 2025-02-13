rule TrojanDropper_Win32_Agent_2147488393_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent"
        threat_id = "2147488393"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 35 00 00 00 eb 08 c6 80 ?? ?? ?? ?? 00 40 80 b8 ?? ?? ?? ?? 00 75 ef 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? 00 00 00 6a 00 e8 ?? 00 00 00 55 8b ec 50 ff 75 08 ff 75 14 e8 ?? 00 00 00 6a 00 6a 00 6a 02 6a 00 6a 00 68 00 00 00 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4e 08 8b 56 04 51 8b c8 e8 ?? ff ff ff 50 ff 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 57 ff d6 53 ff d6 33 c0 b9 11 00 00 00 8d 7c 24 1c f3 ab 8d 54 24 0c 52 8d 44 24 20 50 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_Win32_Agent_2147488393_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent"
        threat_id = "2147488393"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a1 10 67 40 00 b9 81 2a 00 00 99 f7 f9 a3 94 92 40 00 a1 10 67 40 00 b9 81 2a 00 00 99 f7 f9 89 15 98 92 40 00 8b 15 bc 92 40 00 03 15 10 67 40 00 03 15 14 67 40 00 f7 da b9 02 00 00 00 a1 08 68 40 00 e8 17 fb ff ff 8b 1d 94 92 40 00 85 db 7e 30 c7 06 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "software\\borland\\delphi\\rtl" ascii //weight: 1
        $x_1_3 = {00 6f 70 65 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = "writefile" ascii //weight: 1
        $x_1_5 = "shellexecutea" ascii //weight: 1
        $x_1_6 = "C:\\WINDOWS\\SYSTEM32\\Prog.EXE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Agent_DZ_2147511985_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.DZ"
        threat_id = "2147511985"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8d 34 01 8b c1 99 f7 fb 8a 06 2a c1 32 04 3a 41 3b 4c 24 ?? 88 06 7c e4}  //weight: 3, accuracy: Low
        $x_2_2 = {80 34 30 60 40 3b 45 ?? 72 f6}  //weight: 2, accuracy: Low
        $x_1_3 = "fBX`]GK_`]" ascii //weight: 1
        $x_1_4 = {4a 4e 4d 5e 4b 4a 5e 5d 62 1f 67 64 64}  //weight: 1, accuracy: High
        $x_3_5 = {0e 06 0f 06 09 0c 0e 10 21 12 0f 0d 13 29 1b 60 1b 13 2c 1b 8b 20 8b 2c 18 1e 1e 24 2a 29 1f 2c 96 94 97 9f}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Agent_UI_2147598437_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.UI"
        threat_id = "2147598437"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 63 63 65 70 74 3a 20 2a 2f 2a 0d 0a 0d 0a 00 41 67 65 6e 74 25 6c 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {72 65 6c 64 65 6c 00 00 74 72 75 73 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 2f 2f 00 00 50 e8 ?? ?? ?? ?? 83 c4 18 3b c7 74 ?? 40 eb ?? 8d 85 ?? fc ff ff 50 8d 85 ?? fb ff ff 50 e8 ?? ?? ?? ?? 59 8d 85 ?? fb ff ff 59 50 8d 85 ?? fe ff ff 50 e8 ?? ?? ?? ?? 39 7e 10 59 59 74 ?? c7 45 08 80 00 00 00 eb ?? 8b 46 28 89 45 08 8d 85 ?? fe ff ff 50 53}  //weight: 1, accuracy: Low
        $x_1_4 = {68 00 00 01 80 50 ff 15 ?? ?? ?? ?? 89 45 fc ff 76 24 8d 85 ?? fe ff ff 57 57 50 57 57 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 57 57 57 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 57 57 8d 45 e0 57 50 ff 15 ?? ?? ?? ?? ff d3 2b 45 08 3d e8 03 00 00 73 ?? 6a 32 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Agent_TS_2147599449_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.TS"
        threat_id = "2147599449"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "61"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Free DLL Done!" ascii //weight: 10
        $x_10_2 = {53 65 72 76 69 63 65 44 6c 6c 00 00 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 42 49 54 53 5c 50 61 72 61 6d 65 74 65 72 73}  //weight: 10, accuracy: High
        $x_10_3 = "Start DLL Service:" ascii //weight: 10
        $x_1_4 = "Anskya" ascii //weight: 1
        $x_1_5 = "shewoqishui" ascii //weight: 1
        $x_10_6 = "GetSystemDirectoryA" ascii //weight: 10
        $x_10_7 = "OpenSCManagerA" ascii //weight: 10
        $x_10_8 = "ChangeServiceConfigA" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Agent_UM_2147600568_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.UM"
        threat_id = "2147600568"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 01 63 6d 64 20 c7 41 04 2f 63 20 64 c7 41 08 65 6c 20 22 83 c1 0c 68 04 01 00 00 51 6a 00 be ?? ?? ?? ?? ff 76 0c 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? c3}  //weight: 10, accuracy: Low
        $x_1_2 = {8d 7d c4 b9 3c 00 00 00 b8 00 00 00 00 57 f3 aa 5f ba 0c 00 00 00 8b f2 c7 07 ?? ?? ?? ?? c7 47 04 ?? ?? ?? ?? c7 47 08 ?? ?? ?? ?? c7 04 3e ?? ?? ?? ?? c7 44 3e 04 ?? ?? ?? ?? c7 44 3e 08 ?? ?? ?? ?? 03 f2}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 b2 aa 35 a7 2b db ba a2 67 00 00 51 81 c1 7d 12 00 00 35 da f2 78 f1 81 c1 99 00 00 00 85 c9 0f 84 ?? ?? 00 00 59 68 ed 10 40 00 81 f2 fa 31 00 00 ed 8b d8 35 a6 f9 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Agent_UN_2147601304_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.UN"
        threat_id = "2147601304"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 56 ff d7 56 ff 15 ?? ?? ?? ?? 80 7c 30 ff 5c 8b 1d ?? ?? ?? ?? 74 ?? 68 ?? ?? ?? ?? 56 ff d3 8d 85 ?? ?? ff ff 50 6a 00 68 34 31 40 00 56 ff 15 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 50 56 ff d7}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 04 24 58 61 00 00 8b c6 68 ?? ?? ?? ?? 50 e8 ?? ?? ff ff 83 c4 0c 57 57 57 8b c6 50 68 ?? ?? ?? ?? 57 ff 15 ?? ?? ?? ?? 8b 85 ?? ?? 00 00 be ?? ?? ?? ?? 56 e8 ?? ?? 00 00 59 57 ff b5 ?? ?? 00 00 b8 00 00 00 80 57 57 57 50 57 50 68 00 00 cf 00 68 ?? ?? ?? ?? 56 57}  //weight: 1, accuracy: Low
        $x_1_3 = {81 7d f8 00 00 00 01 0f 85 ?? ?? 00 00 f6 45 f4 cc 74 ?? 8b 4d e4 66 81 39 4d 5a 0f 85 ?? ?? 00 00 8b 41 3c 03 c1 81 38 50 45 00 00 0f 85 ?? ?? 00 00 66 81 78 18 0b 01 0f 85 ?? ?? 00 00 2b d9 66 83 78 06 00 0f b7 48 14 8d 4c 01 18 0f 86 ?? ?? 00 00 8b 41 0c 3b d8 72 ?? 8b 51 08 03 d0 3b da 73 ?? f6 41 27 80}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Agent_DA_2147601769_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.DA"
        threat_id = "2147601769"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "141"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {c7 45 9c 41 41 41 41 c7 45 a0 41 41 41 41}  //weight: 100, accuracy: High
        $x_10_2 = "clefdencryption" ascii //weight: 10
        $x_10_3 = "-LIBGCCW32-EH-2-SJLJ-GTHR-MINGW32" ascii //weight: 10
        $x_10_4 = "\\spoolsr.exe" ascii //weight: 10
        $x_10_5 = "\\SYSTEM32\\spoolsr.exe" ascii //weight: 10
        $x_1_6 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Agent_UO_2147602083_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.UO"
        threat_id = "2147602083"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 68 65 6c 6c 33 32 2e 64 6c 6c 00 53 68 65 6c 6c 45 78 65 63 75 74 65 41 00}  //weight: 1, accuracy: High
        $x_1_2 = {66 81 3a 4d 5a 74 09 81 ea 00 00 01 00 90 eb ef 90 8b fa 8b 57 3c 90 8b 54 17 78 8d 54 17 1c}  //weight: 1, accuracy: High
        $x_1_3 = {ff 74 24 04 ff 53 dc 6a 00 68 80 00 00 00 6a 02 6a 00 90 6a 00 68 00 00 00 40 90 50 ff 53 ec 40 74 46 48 50 56 6a 00 54 83 2c 24 50}  //weight: 1, accuracy: High
        $x_1_4 = {50 ff 53 e4 5e 90 ff 53 e8 86 ed 8b 54 24 04 90 8b 04 24 6a 01 6a 00 6a 00 86 ed 50 6a 00 90 6a 00 ff d2 03 fd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Agent_FIY_2147603043_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.gen!FIY"
        threat_id = "2147603043"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 6a 40 68 00 30 00 00 68 00 00 10 00 68 00 00 40 00 ff}  //weight: 1, accuracy: High
        $x_1_2 = {6a 02 6a 00 6a fc ff ?? ?? ?? 50 00 ff ?? ?? ?? 50 00 6a 00 68 ?? ?? 50 00 6a 04 68 ?? ?? 50 00 ff ?? ?? ?? 50 00 ff ?? ?? ?? 50 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 02 6a 00 50 ff ?? ?? ?? 50 00 ff ?? ?? ?? 50 00 6a 00 68 ?? ?? 50 00 6a 0c 68 ?? ?? 50 00 ff ?? ?? ?? 50 00 ff ?? ?? ?? 50 00 [0-32] 68 ?? ?? 50 00 68 00 04 00 00 [0-1] ff ?? ?? ?? 50 00 [0-1] bf ?? ?? 50 00 [0-1] b0 00 [0-1] fc [0-1] f2 ae [0-1] 4f [0-1] be b0 20 50 00 [0-1] b9 03 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 06 35 0d 0d 0d 0d 89 06 83 c6 04 e2 f2 be b0 20 50 00 b9 0c 00 00 00 f3 a4}  //weight: 1, accuracy: High
        $x_1_5 = {6a 00 68 80 00 00 00 [0-1] 6a 03 [0-1] 6a 00 [0-1] 6a 01 [0-1] 68 00 00 00 80 [0-1] 68 ?? ?? 50 00 [0-1] ff ?? ?? ?? 50 00 83 f8 ff 0f}  //weight: 1, accuracy: Low
        $x_1_6 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 00 68 00 00 00 40 ff ?? ?? ?? 50 00 ff ?? ?? ?? 50 00 01 05 ?? ?? 50 00 83 3d ?? ?? 50 00 ff 75 d3 59 eb 16}  //weight: 1, accuracy: Low
        $x_1_7 = {50 00 83 c2 28 8b 02 03 05 ?? ?? 50 00 c7 44 24 28 ?? ?? 50 00 ff e0 61 6a 00 ff 15 ?? ?? 50 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDropper_Win32_Agent_US_2147603257_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.US"
        threat_id = "2147603257"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 65 89 5d f0 e8 ?? ?? ff ff 83 c4 0c ff 75 f0 89 45 f4 ff 15 ?? ?? ?? ?? 8b f8 33 c0 39 5d f4 76 09 fe 0c 38 40 3b 45 f4 72 f7 ff 15 ?? ?? ?? ?? 6a 1a 59 33 d2 f7 f1 68 42 10 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {50 c6 45 f9 2e c6 45 fa 65 c6 45 fb 78 c6 45 fc 65 88 5d fd 80 c2 61 88 55 f8 ff 15 ?? ?? ?? ?? 53 8b f0 8d 45 ec 50 ff 75 f4 57 56 ff 15 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 53 53 53 8d 45 f8 50 53 53 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Agent_CM_2147605590_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.CM"
        threat_id = "2147605590"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {eb 10 66 62 3a 43 2b 2b 48 4f 4f 4b 90 e9}  //weight: 20, accuracy: High
        $x_10_2 = "\\System\\System32.exe" ascii //weight: 10
        $x_10_3 = "\\System\\update.exe" ascii //weight: 10
        $x_10_4 = "\\eMule\\Incoming\\" ascii //weight: 10
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Agent_AS_2147609721_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.AS"
        threat_id = "2147609721"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 40 ff e0 ff 15 ?? ?? ?? ?? c3 55 89 e5 83 ?? ?? e8 ea ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 00 54 45 4d 50 c6 40 04 00 51 8d 85 ?? ?? ?? ?? 68 00 01 00 00 50 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 55 08 8b 75 10 01 d6 8a 16 30 ca ff 45 10 88 16 8b 4d 10 3b 4d 0c 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Agent_BU_2147609917_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.BU"
        threat_id = "2147609917"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "133"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {51 c6 44 24 ?? 5c c6 44 24 ?? 6b c6 44 24 ?? 65 c6 44 24 ?? 72 c6 44 24 ?? 6e c6 44 24 ?? 65 c6 44 24 ?? 6c c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e c6 44 24 ?? 64 c6 44 24 ?? 6c c6 44 24 ?? 6c}  //weight: 100, accuracy: Low
        $x_10_2 = "\\sys_2.dll" wide //weight: 10
        $x_10_3 = "UPDATE_BHO2_SOCKS" ascii //weight: 10
        $x_10_4 = "{55412BAF-86A9-4449-9A59-273A65E50BC2}" ascii //weight: 10
        $x_1_5 = "\\Driver\\Tcpip" wide //weight: 1
        $x_1_6 = "\\Device\\Ipfilterdriver" wide //weight: 1
        $x_1_7 = "IoCallDriver" ascii //weight: 1
        $x_1_8 = "InternetReadFile" ascii //weight: 1
        $x_1_9 = "NdisRegisterProtocol" ascii //weight: 1
        $x_1_10 = "ZwSetSystemInformation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Agent_DL_2147617042_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.DL"
        threat_id = "2147617042"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3c 30 2e 74 0b 90 8a 4c 30 ff 48 80 f9 2e 75 f6}  //weight: 1, accuracy: High
        $x_1_2 = {68 e9 03 00 00 68 (ea|ed) 03 00 00 56 e8 ?? ?? ff ff 83 c4 10 68 04 01 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = "<iframe src='" ascii //weight: 1
        $x_1_4 = "-idx 0 -ip %s-%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Agent_DO_2147619241_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.DO"
        threat_id = "2147619241"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 02 6a 00 68 70 ff ff ff 56 ff 15 ?? ?? ?? ?? 8d ?? ?? ?? 6a 00 52 8d ?? ?? ?? 68 90 00 00 00 50 56 ff 15}  //weight: 5, accuracy: Low
        $x_1_2 = "ADAB6D32-3994-40e2-8C18-2F226306408C" ascii //weight: 1
        $x_1_3 = "E5A42E7E-8130-4f46-BECC-7E43235496A6" ascii //weight: 1
        $x_1_4 = "F918FE01-164A-4e62-9954-EDC8C3964C1B" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Agent_DP_2147621652_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.DP"
        threat_id = "2147621652"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 59 25 6d 25 64 00 00 2e 69 6e 69 00 00 00 00 5c 53 65 72 76 65 72 2e 74 6d 70}  //weight: 1, accuracy: High
        $x_1_2 = {3e 20 6e 75 6c 00 00 20 2f 63 20 20 64 65 6c}  //weight: 1, accuracy: High
        $x_1_3 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" ascii //weight: 1
        $x_1_4 = {51 ff d5 8d ?? ?? ?? ?? 00 00 6a 00 52 ff 15 ?? ?? ?? 00 83 f8 1f 7e 1b 68 88 13 00 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Agent_DQ_2147623106_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.DQ"
        threat_id = "2147623106"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SysMon added to reg." ascii //weight: 1
        $x_1_2 = "-xsysmon" ascii //weight: 1
        $x_1_3 = "UpdMon added to reg." ascii //weight: 1
        $x_1_4 = "-xupdmon" ascii //weight: 1
        $x_5_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 5
        $x_5_6 = {40 55 50 ff 15 ?? ?? 40 00 83 c4 08 85 c0 75 ?? 8b 44 24 24 50 6a 01 68 01 00 10 00 ff 15 ?? ?? 40 00 8b 8c 24 4c 01 00 00 8b 54 24 24 8b f8 89 11 eb 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Agent_DS_2147624174_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.DS"
        threat_id = "2147624174"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ZwLoadDriver" ascii //weight: 1
        $x_1_2 = {ff d6 50 ff d7 89 45 ?? 60 ff 75 ?? 8d bd ?? ?? ff ff 57 ff 55 ?? 8d bd ?? ?? ff ff 57 ff 55 ?? 61}  //weight: 1, accuracy: Low
        $x_1_3 = {66 8b 02 8b e8 81 e5 00 f0 00 00 81 fd 00 30 00 00 75 31 8b 5c 24 10 8b 6c 24 28 43 25 ff 0f 00 00 89 5c 24 10 8b 19 03 c3 8b 1c 30 2b 5d 1c 8b 6c 24 2c 3b dd 75 09 66 81 7c 30 fe c7 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Agent_EB_2147625249_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.EB"
        threat_id = "2147625249"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 65 7a 68 65 6e 00 72 75 6e 64 6c 6c 33 32 2e 65 78 65 00 00 00 00 25 73 2c 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00 00 25 73 79 73 74 65 6d 25}  //weight: 1, accuracy: High
        $x_1_2 = {c2 10 00 81 fe 08 05 00 00 75 1e 68 34 12 00 00 53 ff 15 ?? ?? 40 00 b9 e8 ba 40 00 e8 ?? ?? 00 00 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Agent_UZ_2147636877_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.UZ"
        threat_id = "2147636877"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".3322.org" ascii //weight: 1
        $x_1_2 = "DOWS\\\\system32\\\\Com\\" ascii //weight: 1
        $x_1_3 = "open3389" ascii //weight: 1
        $x_1_4 = "rvices\\poziaini\\" ascii //weight: 1
        $x_2_5 = {75 11 6a 00 6a 7b 68 00 01 00 00 53 e8 ?? ?? ?? ?? eb 0f}  //weight: 2, accuracy: Low
        $x_2_6 = {68 c8 00 00 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 c8 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Agent_EX_2147637247_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.EX"
        threat_id = "2147637247"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c3 f6 6a 02 6a 00 53 56 e8 ?? ?? ?? ?? 6a 00}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 54 3a ff 80 f2 78 e8}  //weight: 2, accuracy: High
        $x_2_3 = {83 fe 04 0f 87 bc 00 00 00 ff 24 b5 ?? ?? ?? 00}  //weight: 2, accuracy: Low
        $x_2_4 = {6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 33 00 36 00 30 00 53 00 61 00 66}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_Win32_Agent_FL_2147637823_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.FL"
        threat_id = "2147637823"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4f 20 6a 02 ff 74 24 10 6a 00 51 ff d0}  //weight: 1, accuracy: High
        $x_2_2 = {c6 45 e8 33 c6 45 e9 36 c6 45 ea 30 c6 45 eb 74 c6 45 ec 72}  //weight: 2, accuracy: High
        $x_1_3 = {57 69 6e 64 6f 77 73 20 ce c4 bc fe b1 a3 bb a4}  //weight: 1, accuracy: High
        $x_1_4 = "%ProgramFiles%\\data.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Agent_FO_2147639597_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.FO"
        threat_id = "2147639597"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 31 2b c3 eb 05 68 f0 0f c7 c8 1b d1 85 d2 75 f6}  //weight: 1, accuracy: High
        $x_1_2 = {7c 02 eb 02 74 fc 7d 02 eb 02 75 fc 7c 05 74 05 75 03 e8 74 f9}  //weight: 1, accuracy: High
        $x_1_3 = {66 9c 73 05 74 08 75 06 e8 e8 02 00 00 00 72 f4 83 c4 04 66 9d 78 03 79 01 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Agent_JZ_2147639601_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.JZ"
        threat_id = "2147639601"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 0e 8a 10 2a d1 88 10 8a ca 8a 16 32 d1 46 88 10 40 4f 75 e1}  //weight: 2, accuracy: High
        $x_2_2 = {8a 1c 28 32 d8 88 1c 28 8b 4c 24 10 40 3b ?? 76 ef}  //weight: 2, accuracy: Low
        $x_1_3 = {8b 44 24 10 3d 10 2f 00 00 0f 87 ?? ?? 00 00 83 f8 0a 0f 82 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {00 70 63 76 69 65 77 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Agent_RH_2147639605_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.RH"
        threat_id = "2147639605"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bf 43 3a 5c 52 be 65 63 79 63}  //weight: 1, accuracy: High
        $x_1_2 = "%SystemRoot%\\system32\\calc.exe" ascii //weight: 1
        $x_1_3 = "cmd /c copy %s %s" ascii //weight: 1
        $x_1_4 = "%s%dcnna.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Agent_RI_2147639606_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.RI"
        threat_id = "2147639606"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\WINDOWS\\iedwf.exe" ascii //weight: 1
        $x_1_2 = "Program Files\\Windows NT\\dnlauncher_.dll" ascii //weight: 1
        $x_1_3 = "C:\\WINDOWS\\qqupdate.dll" ascii //weight: 1
        $x_1_4 = "taskkill.exe /pid %d /f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Agent_JY_2147639751_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.JY"
        threat_id = "2147639751"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 46 10 89 47 74 8b 46 0c 89 47 70}  //weight: 1, accuracy: High
        $x_1_2 = {6a 0b ff d0 8b 45 ?? 85 c0 74 ?? 69 c0 1c 01 00 00 83 c0 04}  //weight: 1, accuracy: Low
        $x_1_3 = "rundll32.exe \"%s\", Launch" ascii //weight: 1
        $x_1_4 = "Global\\__stop" ascii //weight: 1
        $x_1_5 = "%%USERPROFILE%%\\Microsoft\\%s.dll" ascii //weight: 1
        $x_1_6 = "%u.%u.%u.%u:61688//img//" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDropper_Win32_Agent_KA_2147639885_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.KA"
        threat_id = "2147639885"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 40 05 e9 8b 45 ?? 2b 05 ?? ?? ?? ?? 83 e8 05 8b 0d ?? ?? ?? ?? 89 ?? 06}  //weight: 1, accuracy: Low
        $x_1_2 = {64 a1 30 00 00 00 8b 50 0c 8b 42 1c 8b 00 8b 40 08}  //weight: 1, accuracy: High
        $x_1_3 = {6a 0a 99 59 f7 f9 80 c2 30}  //weight: 1, accuracy: High
        $x_1_4 = {c6 45 a2 69 c6 45 a3 66 c6 45 a4 20 c6 45 a5 20 c6 45 a6 20 c6 45 a7 65 c6 45 a8 78 c6 45 a9 69}  //weight: 1, accuracy: High
        $x_1_5 = {47 65 74 50 c7 45 ?? 72 6f 63 41}  //weight: 1, accuracy: Low
        $x_1_6 = {43 61 6e 63 65 6c 44 6c 6c 00 4c 6f 61 64 44 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDropper_Win32_Agent_KB_2147640160_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.KB"
        threat_id = "2147640160"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b0 6c 6a 47 68 ?? ?? ?? 00 c6 44 24 ?? 6b c6 44 24 ?? 72 c6 44 24 ?? 6e}  //weight: 1, accuracy: Low
        $x_1_2 = "s%\\secivreS\\teSlortnoCtnerruC\\METSYS" ascii //weight: 1
        $x_1_3 = {00 30 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 00}  //weight: 1, accuracy: High
        $x_1_4 = "%s\\%d_Index.TEMP" ascii //weight: 1
        $x_1_5 = {4e 65 74 43 72 65 61 74 65 25 64 00 49 4d 47 53 56 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDropper_Win32_Agent_RX_2147641101_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.RX"
        threat_id = "2147641101"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 f2 33 8d 84 24 ?? ?? 00 00 88 94 24 ?? ?? 00 00 8d ?? 01}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 4c 03 01 33 d2 80 f9 5a 0f 94 c2 33 c9 80 3c 18 4d}  //weight: 1, accuracy: High
        $x_1_3 = {64 65 6c 20 25 73 0a 69 66 20 65 78 69 73 74 20 25 73 20 67 6f 74 6f 20 74 72 79 0a 64 65 6c 20 25 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Agent_EAG_2147641885_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.EAG"
        threat_id = "2147641885"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {fe 08 8b 45 ?? 8b 4d ?? 01 c1 8b 45 ?? 8b 55 ?? 01 c2 b0 fa 32 02 88 01 8d 45 fc ff 00}  //weight: 3, accuracy: Low
        $x_1_2 = {8e 8a a7 ba 90 89 89 a0 95 8f ad a0 89 8a 94 96 95 a7 a9 90 95}  //weight: 1, accuracy: High
        $x_1_3 = {a9 bc a9 d8 8b 9c 9a 92 9c 9e a0 89 d5 a0 83 a0}  //weight: 1, accuracy: High
        $x_1_4 = {8a 93 a0 97 97 a7 bc ad a7 9a 96 98 98 9c 95 9f c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Agent_FU_2147642304_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.FU"
        threat_id = "2147642304"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tempVidio.bat" ascii //weight: 1
        $x_1_2 = {59 59 53 53 6a 02 53 53 8d ?? ?? ?? ?? ?? 68 00 00 00 c0 51 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Agent_FV_2147642456_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.FV"
        threat_id = "2147642456"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 10 19 5c cc d4 b1 a6 cc d8 c2 f4 2e 6c 6e 6b 00 fe 81 11 5c 54 61 6f 42 61 6f 5c 74 61 6f 62 61 6f 2e 68 74 6d 6c 00 fe 81 11 5c 54}  //weight: 1, accuracy: High
        $x_1_2 = {5c 68 70 73 65 74 2e 65 78 65 22 20 2f 73 70 2d 20 2f 76 65 72 79 73 69 6c 65 6e 74 00 fd 99 80 5c 6e 6f 64 65 70 61 64 2e 65 78 65 00 fd 9a 80 5c 6e 73 45 78 65 63 2e 64 6c 6c 00 fe 81 11 5c 54 61 6f 42 61 6f 5c 62 61 69 64 75 53 65 74 75 70 2e 62 61 74}  //weight: 1, accuracy: High
        $x_1_3 = {5c 54 61 6f 42 61 6f 5c 42 61 69 64 75 2d 54 6f 6f 6c 62 61 72 2e 65 78 65 00 fe 81 11 5c 54 61 6f 42 61 6f 5c 69 6e 66 6f 2e 64 65 73 63 00 fe 81 11 5c 54 61 6f 42 61 6f 5c 73 6f 67 6f 75 5f 70 69 6e 79 69 6e 5f 6d 69 6e 69 5f 35 32 35 34 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Agent_KL_2147647421_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.KL"
        threat_id = "2147647421"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "BindFile Microsoft" wide //weight: 3
        $x_2_2 = "BindFile.EXE" wide //weight: 2
        $x_3_3 = "BindFile(&A)..." wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Agent_KM_2147647715_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.KM"
        threat_id = "2147647715"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 2d ?? ?? ?? ?? 2d 3d 30 0d 0a 73 65 74 20 2d ?? ?? ?? ?? 2d 3d 31 0d 0a 73 65 74 20 2d ?? ?? ?? ?? 2d 3d 32 0d 0a 73 65 74 20 2d ?? ?? ?? ?? 2d 3d 33 0d 0a 73 65 74 20 2d ?? ?? ?? ?? 2d 3d 34 0d 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "-% $$$$ $$$$$ $$$$$ $   $ $$$$$  >>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Agent_LF_2147655463_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.LF"
        threat_id = "2147655463"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "hhdfshdfghfgfggsdgdgdsfdsfsdfsdfdsafsdfgsdgdfgdfg" ascii //weight: 2
        $x_5_2 = "\\Stub VISUAL\\Release\\Stub VISUAL.pdb" ascii //weight: 5
        $x_1_3 = "dsfgdgdgdfgdsgfdfasdfdasfdsafsadfasdfdfgdsgdfgdfg" ascii //weight: 1
        $x_1_4 = "--@%d--" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Agent_SK_2147744260_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.SK.eml"
        threat_id = "2147744260"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AMMICCOva" ascii //weight: 1
        $x_1_2 = "zasAS" wide //weight: 1
        $x_1_3 = "GASAS.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_Win32_Agent_NW_2147803915_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Agent.NW"
        threat_id = "2147803915"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\esentprf.ini" ascii //weight: 1
        $x_1_2 = "list=203,205,206" ascii //weight: 1
        $x_1_3 = "sc.exe stop" ascii //weight: 1
        $x_1_4 = "sc.exe create" ascii //weight: 1
        $x_1_5 = "type= kernel start= auto binpath=" ascii //weight: 1
        $x_1_6 = "http\\shell\\open\\command" ascii //weight: 1
        $x_1_7 = "%s.old" ascii //weight: 1
        $x_1_8 = "srchasst" ascii //weight: 1
        $x_1_9 = "msagent" ascii //weight: 1
        $x_1_10 = "%s\\%s\\%s%s" ascii //weight: 1
        $x_1_11 = "%s\\dllcache\\%s.sys" ascii //weight: 1
        $x_1_12 = "%s\\drivers\\%s.sys" ascii //weight: 1
        $x_1_13 = "ipfltdrv.sys" ascii //weight: 1
        $x_1_14 = "ipfilterdriver" ascii //weight: 1
        $x_1_15 = "cmd.exe /C ping.exe 127.0.0.1  & del  \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

