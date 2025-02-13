rule TrojanSpy_Win32_Maran_A_2147582586_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Maran.gen!A"
        threat_id = "2147582586"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Maran"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "200"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = "xxSelfinstallxx" ascii //weight: 50
        $x_50_2 = "bntjytutr" ascii //weight: 50
        $x_50_3 = "CreateMutex" ascii //weight: 50
        $x_50_4 = "ReleaseMutex" ascii //weight: 50
        $x_20_5 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 20
        $x_5_6 = "@echo off" ascii //weight: 5
        $x_5_7 = ":loop" ascii //weight: 5
        $x_5_8 = "if exist \"" ascii //weight: 5
        $x_5_9 = "\" goto loop" ascii //weight: 5
        $x_10_10 = {64 65 6c 20 64 65 6c [0-4] 2e 62 61 74}  //weight: 10, accuracy: Low
        $x_1_11 = "winxpnp" ascii //weight: 1
        $x_1_12 = "ipfilter" ascii //weight: 1
        $x_1_13 = "VoiceManagerDown" ascii //weight: 1
        $x_1_14 = "VGADown" ascii //weight: 1
        $x_1_15 = "Audio Adapter" ascii //weight: 1
        $x_1_16 = "\\\\.\\PhysicalDrive0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_10_*) and 3 of ($x_5_*) and 5 of ($x_1_*))) or
            ((3 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_10_*) and 4 of ($x_5_*))) or
            ((4 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Maran_B_2147593088_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Maran.gen!B"
        threat_id = "2147593088"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Maran"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_5_2 = "wmvdsf.ax" ascii //weight: 5
        $x_1_3 = {74 78 74 00 77 65 62 63 66 67 00}  //weight: 1, accuracy: High
        $x_5_4 = "xxxxx.bat" ascii //weight: 5
        $x_1_5 = {50 72 6f 78 79 2d 43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 4b 65 65 70 2d 41 6c 69 76 65 0d 0a}  //weight: 1, accuracy: High
        $x_1_6 = "Accept-Language: zh-cn" ascii //weight: 1
        $x_1_7 = "htons" ascii //weight: 1
        $x_1_8 = "socket" ascii //weight: 1
        $x_1_9 = "StartServiceCtrlDispatcherA" ascii //weight: 1
        $x_1_10 = "SetServiceStatus" ascii //weight: 1
        $x_1_11 = "RegisterServiceCtrlHandlerA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Maran_C_2147593131_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Maran.gen!C"
        threat_id = "2147593131"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Maran"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 5
        $x_5_2 = "delmeml.bat" ascii //weight: 5
        $x_5_3 = "MSAFD Tcpip [TCP/IP]" wide //weight: 5
        $x_5_4 = "DLLCFG" wide //weight: 5
        $x_1_5 = "htons" ascii //weight: 1
        $x_1_6 = "socket" ascii //weight: 1
        $x_1_7 = "WSCGetProviderPath" ascii //weight: 1
        $x_1_8 = "WSCEnumProtocols" ascii //weight: 1
        $x_1_9 = "ipfilter.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Maran_D_2147593142_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Maran.gen!D"
        threat_id = "2147593142"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Maran"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 5
        $x_5_2 = "Accept-Language: zh-cn" ascii //weight: 5
        $x_5_3 = "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, application/vnd.ms-powerpoint, application/vnd.ms-excel, application/msword, */*" ascii //weight: 5
        $x_5_4 = "htons" ascii //weight: 5
        $x_5_5 = "socket" ascii //weight: 5
        $x_1_6 = "Block Sheep Wall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Maran_AT_2147596410_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Maran.AT"
        threat_id = "2147596410"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Maran"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "L1:LandsofAden(" ascii //weight: 1
        $x_1_2 = ";user:" ascii //weight: 1
        $x_1_3 = ";pass:" ascii //weight: 1
        $x_1_4 = "QQQQQSVW" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_6 = "Accept-Language: zh-cn" ascii //weight: 1
        $x_1_7 = "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, application/vnd.ms-powerpoint, application/vnd.ms-excel, application/msword, */*" ascii //weight: 1
        $x_1_8 = {ff ff ff ff 0a 00 00 00 3b ?? ?? ?? ?? 70 61 73 73 3a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanSpy_Win32_Maran_AV_2147599335_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Maran.AV"
        threat_id = "2147599335"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Maran"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "241"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
        $x_20_2 = "del delplme.bat" ascii //weight: 20
        $x_20_3 = "@echo off" ascii //weight: 20
        $x_20_4 = "goto loop" ascii //weight: 20
        $x_20_5 = "od3mdi.dll" ascii //weight: 20
        $x_20_6 = "\\\\.\\PhysicalDrive0" ascii //weight: 20
        $x_20_7 = "MSAFD Tcpip [TCP/IP]" wide //weight: 20
        $x_20_8 = {61 76 70 2e 65 78 65 00}  //weight: 20, accuracy: High
        $x_1_9 = "ipfilter" ascii //weight: 1
        $x_1_10 = "Audio Adapter" ascii //weight: 1
        $x_1_11 = "UBUNTUX" ascii //weight: 1
        $x_1_12 = "VGADown" ascii //weight: 1
        $x_1_13 = "VoiceManagerDown" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 7 of ($x_20_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Maran_BC_2147599342_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Maran.BC"
        threat_id = "2147599342"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Maran"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 ff 31 64 89 21 c7 00 9e d7 9b d6 66 c7 40 04 dd 10 66 c7 40 06 a0 43 c6 40 08 00 c6 40 09 28 c6 40 0a 5f c6 40 0b 15 c6 40 0c 30 c6 40 0d 00 c6 40 0e 01 c6 40 0f 00 c7 02 e5 85 df 93 66 c7 42 04 54 89 66 c7 42 06 f5 4f c6 42 08 00 c6 42 09 00 c6 42 0a 3e c6 42 0b 15 c6 42 0c 00 c6 42 0d 21 c6 42 0e 5b c6 42 0f 00 68 04 01 00 00 68 ?? ?? ?? ?? e8 ?? ?? ff ff 68 ?? ?? ?? ?? e8 ?? ?? ff ff 6a 01 e8 ?? ?? ff ff a1 ?? ?? ?? ?? c6 00 01 b8 ?? ?? ?? ?? a3 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ff ff 33 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {76 67 61 64 6f 77 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 65 74 53 65 72 76 69 63 65 53 74 61 74 75 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 65 74 54 69 6d 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Maran_E_2147605461_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Maran.gen!E"
        threat_id = "2147605461"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Maran"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {57 ff d3 83 c4 14 85 c0 74 09 56 57 e8 ?? ?? ?? ?? 59 59 68 ?? ?? ?? ?? 57 ff d3 59 85 c0 59 74 10 56 57 e8 ?? ?? ?? ?? 83 25 ?? ?? ?? ?? 00 59 59 57 6a 00 ff 35 ?? ?? ?? ?? ff 15}  //weight: 2, accuracy: Low
        $x_3_2 = {80 65 9c 00 6a 18 59 33 c0 8d 7d 9d 68 04 01 00 00 f3 ab 66 ab aa 8d 45 9c 50 ff 15 ?? ?? ?? ?? 8d 45 9c 68 38 30 40 00 50 e8}  //weight: 3, accuracy: Low
        $x_2_3 = {49 50 3d 00 00 00 00 0a 46 54 50 00 00 00 00 50 41 53 53 00 00 00 00 55 53 45 52 00 00 00 00 57 53 50 53 74 61 72 74 75 70 00}  //weight: 2, accuracy: High
        $x_1_4 = {6d 65 73 73 69 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

