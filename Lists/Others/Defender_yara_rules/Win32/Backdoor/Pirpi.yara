rule Backdoor_Win32_Pirpi_A_2147628905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Pirpi.A"
        threat_id = "2147628905"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Pirpi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cb 7d 12 8a 5c 0c ?? 32 da 80 c2 02 88 5c 0c ?? 41 3b c8 7c ee}  //weight: 1, accuracy: Low
        $x_1_2 = {75 60 8d 56 07 33 c9 8a 02 3c 30 7c 0f 3c 39 7f 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win32_Pirpi_C_2147644965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Pirpi.C"
        threat_id = "2147644965"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Pirpi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 54 14 18 8a 1c 38 32 da 88 1c 38 40 3b c1 7c e0}  //weight: 1, accuracy: High
        $x_1_2 = {8a 44 04 10 30 44 0e 04 41 3b ca 72 e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Pirpi_D_2147656938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Pirpi.D"
        threat_id = "2147656938"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Pirpi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7c 24 1c 57 33 f6 ff d3 85 c0 75 1a 8b 2d e0 80 00 10 83 fe 14 7f 0f 68 ?? ?? 00 00 46 ff d5 57 ff d3 85 c0 74 ec}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 7c 24 0c f3 a5 8b b4 24 ?? ?? 00 00 85 ed 7e 21 8d 4c 24 0c 53 8a 9c 24 00 00 00 8b c6 2b ce 8b fd 8a 14 01 32 d3 30 10 88 14 01 40 4f 75 f2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Pirpi_E_2147696137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Pirpi.E!dha"
        threat_id = "2147696137"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Pirpi"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 66 8b 04 55 ?? ?? ?? ?? 8b f0 33 d2 66 8b 15 ?? ?? ?? ?? 33 f2 81 c6}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 66 8b 14 5d ?? ?? ?? ?? f3 ab 8b 0d ?? ?? ?? ?? 66 8b 04 5d ?? ?? ?? ?? 81 e1 ff ff 00 00 8d 7c 24 0c 33 d1 33 c1}  //weight: 1, accuracy: Low
        $x_1_3 = {33 c0 8d 7c 24 0c 33 d2 66 8b 14 5d ?? ?? ?? ?? f3 ab 8b 0d ?? ?? ?? ?? 66 8b 04 5d ?? ?? ?? ?? 81 e1 ff ff 00 00 8d 7c 24 0c}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 55 0c 03 55 fc 8b 45 fc 8a 0a 32 4c 05 ?? 8b 55 0c 03 55 fc 88 0a}  //weight: 1, accuracy: Low
        $x_1_5 = {8d 4c 24 0c 53 8a 5c 24 90 01 01 8b c6 2b ce 8b fd 8a 14 01 32 d3 30 10 88 14 01}  //weight: 1, accuracy: High
        $x_1_6 = {51 6a 66 e8 ?? ?? ?? ?? 83 c4 0c 8d 7d ?? ba ?? ?? ?? ?? 83 c9 ff 33 c0 f2 ae f7 d1 2b f9}  //weight: 1, accuracy: Low
        $x_1_7 = {c7 45 fc 01 00 00 00 0f be 45 08 89 45 f4 8b 4d f4 89 4d f0 83 6d f0 01 83 7d f0 00 74 ?? 83 6d f0 01 83 7d f0 00}  //weight: 1, accuracy: Low
        $x_1_8 = {83 ec 10 8b 44 24 14 8d 4c 24 00 89 44 24 00 33 c0 51 c7 44 24 08 ?? ?? 40 00 89 44 24 0c 89 44 24 10 ff 15 ?? ?? 40 00 83 c4 10 c3}  //weight: 1, accuracy: Low
        $x_1_9 = {6a 00 56 57 53 (e8|ff) [0-4] 83 f8 ff 74 ?? 85 c0 74 ?? 2b f0 03 f8 85 f6 75 ?? 8b [0-3] 5f 2b c6 5e 5d 5b c3 (e8|ff 15) [0-4] 3d 4c 27 00 00 74 ?? 5f 5e 5d (33 c0|83) 5b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Pirpi_G_2147696437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Pirpi.G!dha"
        threat_id = "2147696437"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Pirpi"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 44 24 3c 72 c6 44 24 3d 75 c6 44 24 3e 6e c6 44 24 3f 64 c6 44 24 40 6c c6 44 24 41 6c c6 44 24 42 33 c6 44 24 43 32 c6 44 24 44 20 c6 44 24 45 22 88 5c 24 46}  //weight: 1, accuracy: High
        $x_1_2 = {00 55 70 64 76 61 4d 74 00}  //weight: 1, accuracy: High
        $x_1_3 = "vv;expires = sat,01-jan-2000 00:00:00 gmt" ascii //weight: 1
        $x_1_4 = {76 63 6c 2e 74 6d 70 00 68 74 74 70 3a 2f 2f 25 73 2f 25 73 2e 25 73}  //weight: 1, accuracy: High
        $x_1_5 = {25 73 69 6e 64 65 78 25 32 2e 32 64 5f 25 64 2e 68 74 6d 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Pirpi_P_2147696749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Pirpi.P!dha"
        threat_id = "2147696749"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Pirpi"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1000"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Opening Service ..... " ascii //weight: 1
        $x_3_2 = "PJ_jX8RZMB9hmzKEnCg4idlFA05LDu2ftkYGa3TpWIrc6vQ.NoVxO1by7" ascii //weight: 3
        $x_1_3 = "-install" ascii //weight: 1
        $x_1_4 = "-show" ascii //weight: 1
        $x_1_5 = "-remove" ascii //weight: 1
        $x_1_6 = "HTTP/1.1 404 Not Found" ascii //weight: 1
        $x_1_7 = "Server: Microsoft-IIS/6.0" ascii //weight: 1
        $x_1_8 = "E* CreateFile(%s) Error(%d)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Pirpi_R_2147749676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Pirpi.R!dha"
        threat_id = "2147749676"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Pirpi"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TrustUdpServer::_handleSnifferRequest" ascii //weight: 1
        $x_1_2 = "TrustUdpServer.cpp" ascii //weight: 1
        $x_1_3 = "CN=Microsoft Corporation,L=Redmond,S=Washington,C=US" ascii //weight: 1
        $x_1_4 = "This is a vendor's account for the Help and Support Service" ascii //weight: 1
        $x_1_5 = "This is a Machine account for IIS Service" ascii //weight: 1
        $x_1_6 = "ABCUDEFZYXGHIJTKLMNOPQRSVWabcdefgh34ijkzyxlmnorstuvw012567pq89+/" ascii //weight: 1
        $x_1_7 = "-serverP" ascii //weight: 1
        $x_1_8 = "CommandParser::parseCommand" ascii //weight: 1
        $x_1_9 = "sniffer\\CommandParser.cpp" ascii //weight: 1
        $x_1_10 = "CommandParser::_parseIpParam" ascii //weight: 1
        $x_1_11 = "HideLoadder.cpp" ascii //weight: 1
        $x_1_12 = "invalid pe file, the program must be %d bit" ascii //weight: 1
        $x_1_13 = "HideLoadder::_peAlloc" ascii //weight: 1
        $x_1_14 = "HideLoadder::_peBuild" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

