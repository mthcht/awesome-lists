rule Virus_Win32_Viking_B_2147580900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Viking.gen!B"
        threat_id = "2147580900"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Viking"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\AVP" ascii //weight: 1
        $x_1_4 = "Cool_GameSetup.exe" ascii //weight: 1
        $x_1_5 = "c:\\GK.TMP" ascii //weight: 1
        $x_1_6 = "Desktop_1.ini" ascii //weight: 1
        $x_1_7 = "MSN Gamin Zone" ascii //weight: 1
        $x_1_8 = "C:\\Program Files\\WinRAR\\winrar.exe\" u -as -ep1 -inul -ibck" ascii //weight: 1
        $x_1_9 = "safeboxTray.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Viking_2147580901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Viking.gen!dll"
        threat_id = "2147580901"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Viking"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {7e 2e c7 45 f8 01 00 00 00 8b 45 fc 8b 55 f8 8a 5c 10 ff 80 c3 80 8d 45 f4 8b d3}  //weight: 3, accuracy: High
        $x_3_2 = {d5 d2 cc c4 ef f7 ee ec ef e1 e4 d4 ef c6 e9 ec}  //weight: 3, accuracy: High
        $x_3_3 = {dc ed e9 e3 f2 ef f3 ef e6 f4 dc}  //weight: 3, accuracy: High
        $x_2_4 = {e8 f4 f4 f0 ba af af}  //weight: 2, accuracy: High
        $x_1_5 = "c:\\1.txt" ascii //weight: 1
        $x_1_6 = {64 33 3a 00 ff ff ff ff 03}  //weight: 1, accuracy: High
        $x_1_7 = {64 34 3a 00 ff ff ff ff 03}  //weight: 1, accuracy: High
        $x_1_8 = "ACDSee4.exe" ascii //weight: 1
        $x_1_9 = "Uedit32.exe" ascii //weight: 1
        $x_1_10 = " /hehe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_3_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Viking_JB_2147598552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Viking.JB"
        threat_id = "2147598552"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Viking"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7e 2e c7 45 f8 01 00 00 00 8b 45 fc 8b 55 f8 8a 5c 10 ff 80 c3 80 8d 45 f4 8b d3 e8 ?? ?? ?? ?? 8b 55 f4 8b c7 e8 ?? ?? ?? ?? ff 45 f8 4e 75 d9}  //weight: 5, accuracy: Low
        $x_1_2 = {0f 84 2d 01 00 00 6a 00 53 e8 ?? ?? ff ff 8b f0 81 fe 00 00 00 01 0f 83 11 01 00 00 3b 35 ?? ?? ?? ?? 7c 34}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 55 fc e8 ?? ?? ff ff 8b 85 ?? ?? ff ff e8 ?? ?? ff ff 56 57 e8 ?? ?? ff ff 85 c0 75 84 57 e8 ?? ?? ff ff c7 06 16 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Viking_JF_2147598553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Viking.JF"
        threat_id = "2147598553"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Viking"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {7e 2e c7 45 f8 01 00 00 00 8b 45 fc 8b 55 f8 8a 5c 10 ff 80 c3 80 8d 45 f4 8b d3}  //weight: 4, accuracy: High
        $x_3_2 = {8b 07 83 78 08 01 75 f1 68 c8 00 00 00}  //weight: 3, accuracy: High
        $x_3_3 = {ff ff 3d 03 01 00 00 0f ?? ?? ?? ?? ?? 3d ea 00 00 00 75}  //weight: 3, accuracy: Low
        $x_2_4 = {f6 40 1c 01 74 27 68 30 75 00}  //weight: 2, accuracy: High
        $x_2_5 = {8b 07 83 78 04 00 74 3c 68 d0 07 00 00}  //weight: 2, accuracy: High
        $x_1_6 = {81 38 6b 42 79 44 74}  //weight: 1, accuracy: High
        $x_1_7 = {83 f8 01 1b c0 40 88 45 fb 53}  //weight: 1, accuracy: High
        $x_1_8 = {eb 04 c6 45 fb 00 80 7d fb 00}  //weight: 1, accuracy: High
        $x_1_9 = "FindResourceA" ascii //weight: 1
        $x_1_10 = "WriteProcessMemory" ascii //weight: 1
        $x_1_11 = "WNetOpenEnumA" ascii //weight: 1
        $x_1_12 = "WNetEnumResourceA" ascii //weight: 1
        $x_1_13 = "WNetCloseEnum" ascii //weight: 1
        $x_1_14 = "WNetCancelConnectionA" ascii //weight: 1
        $x_1_15 = "WNetCancelConnection2A" ascii //weight: 1
        $x_1_16 = "WNetAddConnection2A" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_3_*) and 10 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 7 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 9 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Viking_A_2147602717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Viking.dll.gen!A"
        threat_id = "2147602717"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Viking"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e3 ba dc b1 ae f4 f8 f4 00}  //weight: 1, accuracy: High
        $x_2_2 = {d5 d2 cc c4 ef f7 ee ec ef e1 e4 d4 ef c6 e9 ec e5 c1 00}  //weight: 2, accuracy: High
        $x_1_3 = {f3 ef e6 f4 f7 e1 f2 e5 dc ed e9}  //weight: 1, accuracy: High
        $x_1_4 = {00 ae e5 f8 e5 00}  //weight: 1, accuracy: High
        $x_1_5 = {d5 d2 cc cd cf ce ae c4 cc cc 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Viking_2147642443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Viking!remnants"
        threat_id = "2147642443"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Viking"
        severity = "Critical"
        info = "remnants: remnants of a virus"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 00 00 00 00 5b 81 eb 05 02 40 00 64 8b 3d 30 00 00 00 8b 7f 0c 8b 7f 1c 8b 3f 8b 7f 08 89 bb}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 51 83 c1 0a 8b 11 52 51 ba 4d 5a 90 00 89 11 56 ff d0}  //weight: 1, accuracy: High
        $x_1_3 = {52 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 83 c2 44 52 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Viking_SA_2147779444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Viking.SA!MTB"
        threat_id = "2147779444"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Viking"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 66 20 65 78 69 73 74 20 22 43 3a 5c [0-16] 2e 65 78 65 22 20 67 6f 74 6f 20 74 72 79 31}  //weight: 1, accuracy: Low
        $x_1_2 = {72 65 6e 20 22 43 3a 5c [0-16] 2e 65 78 65 2e 65 78 65 22 20 22 [0-16] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_3 = {69 66 20 65 78 69 73 74 20 22 43 3a 5c [0-16] 2e 65 78 65 2e 65 78 65 22 20 67 6f 74 6f 20 74 72 79 32}  //weight: 1, accuracy: Low
        $x_1_4 = "del \"C:\\TEMP\\$$ab2890.bat\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Viking_AVK_2147922892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Viking.AVK!MTB"
        threat_id = "2147922892"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Viking"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {50 8d 95 60 fd ff ff 33 c0 e8 a0 a7 ff ff 8b 95 60 fd ff ff 8d 45 ec 59 e8 c9 b3 ff ff 8b 45 ec e8 75 b5 ff ff 50 e8 e3 c2 ff ff}  //weight: 5, accuracy: High
        $x_3_2 = {68 b4 83 40 00 8d 95 44 fd ff ff 33 c0 e8 ?? ?? ?? ?? ff b5 44 fd ff ff 68 cc 83 40 00 68 d8 83 40 00 8d 95 40 fd ff ff 33 c0 e8 ?? ?? ?? ?? ff b5 40 fd ff ff 68 ec 83 40 00 68 f8 83 40 00 68 10 84 40 00 ff 75 ec 68 20 84 40 00 8d 95 38 fd ff ff 33 c0}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

