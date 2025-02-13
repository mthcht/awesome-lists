rule Trojan_Win32_BHO_LI_2147601435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.LI"
        threat_id = "2147601435"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "37"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "PendingFileRenameOperations" ascii //weight: 5
        $x_5_2 = "Internet Explorer\\SearchScopes" ascii //weight: 5
        $x_5_3 = "regsvr32 /s \"%s" ascii //weight: 5
        $x_5_4 = "iebho.dll" ascii //weight: 5
        $x_5_5 = "UpdateTime" ascii //weight: 5
        $x_5_6 = "hSkinMutex" ascii //weight: 5
        $x_5_7 = "DownWomMem" ascii //weight: 5
        $x_1_8 = "SOFTWARE\\navoct" ascii //weight: 1
        $x_1_9 = "iewoptimem.exe" ascii //weight: 1
        $x_1_10 = "IETool.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BHO_LJ_2147601578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.LJ"
        threat_id = "2147601578"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 69 6e 64 73 69 74 65 6f 6e 6c 69 6e 65 2e 63 6f 6d 00}  //weight: 10, accuracy: High
        $x_2_2 = {6a 00 89 4d f8 68 ?? ?? ?? ?? c6 45 ?? 75 c6 45 ?? 72 c6 45 ?? 6c c6 45 ?? 63 c6 45 ?? 6c c6 45 ?? 69 c6 45 ?? 63 c6 45 ?? 6b c6 45 ?? 73 c6 45 ?? 72 c6 45 ?? 65 c6 45 ?? 66}  //weight: 2, accuracy: Low
        $x_2_3 = {56 51 50 8d 85 ?? ?? ff ff 68 ?? ?? ?? ?? 50 e8 ?? ?? 00 00 be ?? ?? 00 00 8d 85 ?? ?? ff ff 56 6a 00 50 e8 ?? ?? 00 00 83 c4 1c}  //weight: 2, accuracy: Low
        $x_1_4 = {6c 69 76 65 2e 00}  //weight: 1, accuracy: High
        $x_1_5 = {6d 73 6e 2e 00}  //weight: 1, accuracy: High
        $x_1_6 = {79 61 68 6f 6f 2e 00}  //weight: 1, accuracy: High
        $x_1_7 = {67 6f 6f 67 6c 65 2e 00}  //weight: 1, accuracy: High
        $x_1_8 = {62 68 6f 3d 31 26 76 3d 31 38 26 73 65 3d 25 73 26 75 73 65 72 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_9 = {3f 70 3d 00 26 70 3d 00 3f 71 3d 00 26 71 3d 00}  //weight: 1, accuracy: High
        $x_1_10 = "POST /search?q=%s HTTP/1.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BHO_2147602518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO"
        threat_id = "2147602518"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\{86A44EF7-78FC-4e18-A564-B18F806F7F56}" ascii //weight: 1
        $x_1_2 = "ConnectionServices.DLL" ascii //weight: 1
        $x_1_3 = "InternetOpenA" ascii //weight: 1
        $x_1_4 = "HttpSendRequestA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_2147602518_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO"
        threat_id = "2147602518"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft Visual C++ Runtime Library" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\{18CB1A7B-94CD-4582-8022-ADA16851E44B}" ascii //weight: 1
        $x_1_3 = "ConnectionServices.DLL" ascii //weight: 1
        $x_1_4 = "gofuckyourself.com" ascii //weight: 1
        $x_1_5 = "bbs.adultwebmasterinfo.com" ascii //weight: 1
        $x_1_6 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_7 = "HttpOpenRequestA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_X_2147602577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.X"
        threat_id = "2147602577"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {84 b2 96 b1 b4 ba 1a 10 b6 9c 00 aa 00 34 1d 07 61 16 0c d3 af cd d0 11 8a 3e 00 c0 4f c9 e2 6e a0 15 a7 34 87 65 d0 11 92 4a 00 20 af c7 ac 4d 25 44 2c 33 cb 26 d0 11 b4 83 00 c0 4f d9 01 19 ff f1 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b 1f f2 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b 00 04 02 00 00 00 00 00 c0 00 00 00 00 00 00 46}  //weight: 3, accuracy: High
        $x_1_2 = {8d 45 c4 50 68 00 00 00 10 ff 75 08 c7 45 c4 3c 00 00 00 e8 ?? ?? 00 00 59 50 ff 75 08 ff 15 ?? ?? 00 10}  //weight: 1, accuracy: Low
        $x_3_3 = {3d e0 93 04 00 76 0b ff 75 ec 8b 4d 08 e8 ?? ?? 00 00 12 00 88 1d ?? ?? 00 10 ff 15 ?? ?? 00 10 2b 05 ?? ?? 00 10}  //weight: 3, accuracy: Low
        $x_1_4 = {44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 1, accuracy: High
        $x_1_5 = "InternetCrackUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BHO_Y_2147603697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.Y"
        threat_id = "2147603697"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = {61 16 0c d3 af cd d0 11 8a 3e 00 c0 4f c9 e2 6e 25 44 2c 33 cb 26 d0 11 b4 83 00 c0 4f d9 01 19 ff f1 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b 08 00 00 00 68 00 72 00 65 00 66 00 00 00 00 00 ff ff ff ff 0c 00 00 00 70 61 67 65 61 64 2f 69 63 6c 6b 3f 00 00 00 00 ff ff ff ff ?? ?? 00 00 68 74 74 70 3a 2f 2f 70 61 67 65 61 64 32 2e 67 6f 6f 67 6c 65 73 79 6e 64 69 63 61 74 69 6f 6e 73 73 69 74 65 2e 63 6f 6d 2f 70 61 67 65 61 64 2f 69 63 6c 6b 3f 73 61 3d 6c 26 61 69 3d 42 38 64 58 73 65}  //weight: 10, accuracy: Low
        $x_1_3 = "IE(AL(\"%s\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_A_2147606288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.A"
        threat_id = "2147606288"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_2 = "ser.exe" ascii //weight: 1
        $x_1_3 = "iup.exe" ascii //weight: 1
        $x_1_4 = "bho.dll" ascii //weight: 1
        $x_1_5 = "play.dll" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" ascii //weight: 1
        $x_1_7 = "Explorer\\Run" ascii //weight: 1
        $x_1_8 = "fuckyou" ascii //weight: 1
        $x_1_9 = "%s,Always" ascii //weight: 1
        $x_1_10 = "microsoft_lock" ascii //weight: 1
        $x_1_11 = "\\regsvr32.exe" ascii //weight: 1
        $x_1_12 = ".txt" ascii //weight: 1
        $x_1_13 = ".bmp" ascii //weight: 1
        $x_1_14 = "sysoption.ini" ascii //weight: 1
        $x_1_15 = "\\\\.\\PhysicalDrive%d" ascii //weight: 1
        $x_1_16 = "winio.sys" ascii //weight: 1
        $x_1_17 = "\\\\.\\Scsi%d:" ascii //weight: 1
        $x_1_18 = {51 8a 44 24 03 53 56 57 a2 ?? c5 40 00 bf ?? c0 40 00 83 c9 ff 33 c0 33 d2 33 f6 f2 ae f7 d1 49}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_F_2147609618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.F"
        threat_id = "2147609618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 25 8d c3 50 5c 92 41 a7 46 ac 6f e5 19 83 1e d6 c9 ea 79 fa ba ce 11 8c 82 00 aa 00 4b a9 0b e8 c9 ea 79 f9 ba ce 11 8c 82 00 aa 00 4b a9 0b eb c9 ea 79 f9 ba ce 11 8c 82 00 aa 00 4b a9 0b ec c9 ea 79 f9 ba ce 11 8c 82 00 aa 00 4b a9 0b e4 c9 ea 79 f9 ba ce 11 8c 82 00 aa 00 4b a9 0b}  //weight: 1, accuracy: High
        $x_1_2 = {5c 69 73 6f 63 6f 6e 66 69 67 2e 63 66 67 00}  //weight: 1, accuracy: High
        $x_1_3 = ".go2easy.com/iso" ascii //weight: 1
        $x_1_4 = "73A7FFA7-AA3A-49E5-A777-713B7DB78E9C" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_K_2147611022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.K"
        threat_id = "2147611022"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 40 33 c0 59 8d bd ?? ?? ff ff 88 95 ?? ?? ff ff 68 3f 00 0f 00 f3 ab 66 ab 68 ?? ?? ?? ?? 68 02 00 00 80 8d ?? ?? 89 ?? ?? c7 ?? ?? 04 01 00 00 aa}  //weight: 10, accuracy: Low
        $x_2_2 = {69 65 67 75 69 64 65 2e 63 6f 2e 6b 72 2f [0-32] 2e 70 68 70 3f}  //weight: 2, accuracy: Low
        $x_2_3 = "C:\\Program Files\\ieguide_plus\\WSock.dll" ascii //weight: 2
        $x_2_4 = "SOFTWARE\\ieguide_plus" ascii //weight: 2
        $x_1_5 = "ieguidekeyword" ascii //weight: 1
        $x_1_6 = "StartDll" ascii //weight: 1
        $x_1_7 = "Internet Explorer_Server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BHO_Q_2147615788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.Q"
        threat_id = "2147615788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 0c 56 8b 74 24 0c 33 c9 85 f6 89 30 8b 44 24 08 7e 34 57 eb 08 8d a4 24 00 00 00 00 90 8a 14 01 0f be fa 81 e7 03 00 00 80 79 05 4f 83 cf fc 47 74 03 80 c2 fc 88 14 01 83 c1 01 3b ce 7c de 5f c6 04 30 00 5e c3}  //weight: 1, accuracy: High
        $x_1_2 = "{mrds{2srivvsvAjyrgtmsr(-" ascii //weight: 1
        $x_1_3 = "Wsjt{evi\\Qmgvswsjt\\Mrtivrit Ixplsviv\\Ri{ [mrds{w\\Ells{" ascii //weight: 1
        $x_1_4 = "whill762dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_BHO_R_2147616153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.R"
        threat_id = "2147616153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 65 78 70 6c 6f 72 65 2e 65 78 65 00 00 00 00 6f 70 65 6e}  //weight: 1, accuracy: High
        $x_1_2 = {00 63 6f 6d 6d 65 6e 74 32 00}  //weight: 1, accuracy: High
        $x_1_3 = {2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_4 = {00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 42 69 6e 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_R_2147616153_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.R"
        threat_id = "2147616153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "211"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "Software\\Microsoft\\Internet Explorer\\New Windows\\Allow" ascii //weight: 100
        $x_100_2 = "window.onerror=function(){return true;}" ascii //weight: 100
        $x_10_3 = {68 74 74 70 3a 2f 2f [0-16] 63 6c 69 63 6b 7a 63 6f 6d 70 69 6c 65 2e 63 6f 6d 2f 63 2f 25 6c 75 2f 25 6c 75 2f 25 6c 75 2f 25 6c 75}  //weight: 10, accuracy: Low
        $x_10_4 = {68 74 74 70 3a 2f 2f [0-16] 75 61 74 6f 6f 6c 62 61 72 2e 63 6f 6d 2e 63 6f 6d 2f 63 2f 25 6c 75 2f 25 6c 75 2f 25 6c 75 2f 25 6c 75}  //weight: 10, accuracy: Low
        $x_1_5 = "exe.vak" ascii //weight: 1
        $x_1_6 = "exe.sgsmsm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BHO_AB_2147616412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.AB"
        threat_id = "2147616412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 6e 74 65 72 6e 65 74 00 65 78 70 6c 6f 72 65 72 00 00 00 3a 5c 78 30 30 00 63 72 69 70 74}  //weight: 1, accuracy: High
        $x_1_2 = {49 6e 74 65 72 6e 65 74 00 45 78 70 6c 6f 72 65 72 5f 54 72 69 64 65 6e 74 44 6c 67 46 72 61 6d 65 00 00 00 49 45 46 72 61 6d 65 00 2a 2e 2a}  //weight: 1, accuracy: High
        $x_1_3 = {72 62 00 00 77 62 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 78 30 30 2e 6c 6e 6b 00 00 00 00 4d 65 64 69 61 00 00 00 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_U_2147616664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.U"
        threat_id = "2147616664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "61"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "80EF304A-B1C4-425C-8535-95AB6F1EEFB8" wide //weight: 10
        $x_10_2 = {73 00 74 00 61 00 72 00 74 00 3d 00 30 00 00 00 2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e}  //weight: 10, accuracy: High
        $x_10_3 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" wide //weight: 10
        $x_10_4 = "<a class=yschttl href=" wide //weight: 10
        $x_10_5 = "results/router" wide //weight: 10
        $x_10_6 = "results/pop" wide //weight: 10
        $x_1_7 = "BHO_MyJavaCore.DLL" ascii //weight: 1
        $x_1_8 = "MJCore.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BHO_AK_2147620192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.AK"
        threat_id = "2147620192"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 77 00 69 00 6e 00 70 00 72 00 6f 00 63 00 2e 00 44 00 4c 00 4c 00 [0-8] 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 [0-4] 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 28 00 52 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {76 6f 69 64 63 6f 64 65 2e 33 33 32 32 2e 6f 72 67 00}  //weight: 1, accuracy: High
        $x_1_3 = "A2DF4DBF-29B4-42A4-BD19-2CBC443E2E84" ascii //weight: 1
        $x_1_4 = "WINPROC.msiebr." ascii //weight: 1
        $x_1_5 = "InternetAttemptConnect" ascii //weight: 1
        $x_1_6 = "InternetSetStatusCallback" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_AL_2147620477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.AL"
        threat_id = "2147620477"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "config_cookies_0_" wide //weight: 1
        $x_1_2 = "config_keyword_" wide //weight: 1
        $x_1_3 = "HttpSendRequestW" ascii //weight: 1
        $x_1_4 = "InternetConnectW" ascii //weight: 1
        $x_1_5 = {2e 00 63 00 6f 00 6d 00 2f 00 63 00 2f 00 76 00 [0-4] 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
        $x_1_6 = {2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_AM_2147620889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.AM"
        threat_id = "2147620889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 49 6d 70 6c 65 6d 65 6e 74 65 64 20 43 61 74 65 67 6f 72 69 65 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 52 65 71 75 69 72 65 64 20 43 61 74 65 67 6f 72 69 65 73 00}  //weight: 1, accuracy: High
        $x_2_3 = "A0E1054B-01EE-4D57-A059-4D99F339709F" wide //weight: 2
        $x_3_4 = {6a 40 57 56 ff d3 33 c0 85 ff 76 0b 80 34 30 ?? 83 c0 01 3b c7 72 f5}  //weight: 3, accuracy: Low
        $x_3_5 = {6a 40 57 56 ff d5 33 c9 85 ff 76 ?? 8a 04 31 8a d0 f6 d2 32 d0 80 e2 ?? f6 d0 32 d0 88 14 31}  //weight: 3, accuracy: Low
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

rule Trojan_Win32_BHO_AN_2147621007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.AN"
        threat_id = "2147621007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hycg_Main" ascii //weight: 1
        $x_1_2 = "Explorer Bars\\{161F3857-CD86-4946-B2AB-5A35BCFF8905}" ascii //weight: 1
        $x_1_3 = "\\dttd" ascii //weight: 1
        $x_1_4 = "s 'IEHelper Band'" ascii //weight: 1
        $x_1_5 = {55 52 53 4f 46 54 20 57 33 32 44 41 53 4d 00 2d 3d 43 48 49 4e 41 20 43 52 41 43 4b 49 4e 47 20 47 52 4f 55 50 3d 2d 00 4f 6c 6c 79 44 62 67 00 54 52 57 32 30 30 30}  //weight: 1, accuracy: High
        $x_1_6 = "NTice.sys" ascii //weight: 1
        $x_1_7 = "NtQuerySystemInformation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_AP_2147621388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.AP"
        threat_id = "2147621388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_2 = {5c 73 79 73 74 65 6d 33 32 5c 72 65 67 73 76 72 33 32 2e 65 78 65 20 61 64 73 6c 64 70 62 ?? 2e 64 6c 6c 20 2f 73}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 73 79 73 74 65 6d 33 32 5c 61 64 73 6c 64 70 62 ?? 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_AR_2147621651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.AR"
        threat_id = "2147621651"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 62 61 72 73 65 61 72 63 68 2e 63 6f 2e 6b 72 2f 50 72 6f 2f 63 6e 74 2e 70 68 70 3f 6d 61 63 3d 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 62 61 72 73 63}  //weight: 1, accuracy: High
        $x_1_2 = "Browser Helper Objects\\{3ABB8E8B-6852-481F-8A74-18BABCA7A74B" ascii //weight: 1
        $x_1_3 = "http://install2.mdvirus.com/DB/" ascii //weight: 1
        $x_1_4 = "%s /s /u %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_AS_2147622586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.AS"
        threat_id = "2147622586"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CLSID = s '{8FF40C83-9F3A-449C-8874-4C867931D5EA}'" ascii //weight: 1
        $x_1_2 = "IE.IEE.1 = s 'IE" ascii //weight: 1
        $x_1_3 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_4 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00 49 45 2e 44 4c 4c}  //weight: 1, accuracy: High
        $x_1_5 = "Microsoft Corporation" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_BHO_AU_2147624103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.AU"
        threat_id = "2147624103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 6f 72 64 70 61 64 00 72 67 2e 64 61 74 00 00 5c 62 69 67 64 76 2e 64 61 74}  //weight: 1, accuracy: High
        $x_1_2 = {49 6e 73 74 61 6c 6c 00 5c 74 6f 64 6f 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = {68 74 74 70 3a 2f 2f 34 2e 67 75 7a 68 69 6a 69 6a 69 6e 2e 63 6f 6d 2f 62 69 67 64 2f [0-8] 2f 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 54 65 6d 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_AV_2147624104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.AV"
        threat_id = "2147624104"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {49 6e 73 74 61 6c 6c 00 5c 74 6f 64 6f 2e 65 78 65}  //weight: 5, accuracy: High
        $x_5_2 = "http://4.guzhijijin.com" ascii //weight: 5
        $x_1_3 = {71 71 73 68 65 6c 00 00 72 65 67 2e 64 61 74}  //weight: 1, accuracy: High
        $x_1_4 = {33 36 30 75 70 00 00 00 72 65 67 2e 64 61 74}  //weight: 1, accuracy: High
        $x_1_5 = {52 61 76 4d 6f 6e 53 00 73 6f 6e 69 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BHO_BA_2147625211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.BA"
        threat_id = "2147625211"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "7D714E45-5CE2-4743-A6C3-2FFFE9F2DF07" ascii //weight: 1
        $x_1_2 = {49 6e 73 74 61 6c 6c 48 6f 6f 6b [0-4] 6d 69 6c 65 6d 61 6c 6c 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_3 = "reward/mymile/mymile01/update_dll.php" ascii //weight: 1
        $x_1_4 = "clsid_mymile_01.xml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_BC_2147625410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.BC"
        threat_id = "2147625410"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 [0-4] 4c 00 55 72 6c 4d 6b 53 65 74 53 65 73 73 69 6f 6e 4f 70 74 69 6f 6e [0-4] 75 72 6c 6d 6f 6e 2e 64 6c 6c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {25 01 00 00 80 79 05 48 83 c8 fe 40 3d ?? ?? ?? ?? 75 06 ff 15 05 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {99 b9 03 00 00 00 f7 f9 81 fa ?? ?? ?? ?? 75 06 ff 15 05 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_BD_2147625511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.BD"
        threat_id = "2147625511"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/baidu?word=" ascii //weight: 1
        $x_1_2 = {45 78 70 6c 6f 72 65 57 43 6c 61 73 73 00 00 00 43 61 62 69 6e 65 74 57 43 6c 61 73 73}  //weight: 1, accuracy: High
        $x_1_3 = {6a 32 ff 15 ?? ?? 00 10 8b 45 f4 85 c0 75 05 a1 ?? ?? 00 10 50 ff 75 f8 6a 0c ff 35 ?? ?? 00 10 ff d6 4f 75 db}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_BH_2147626273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.BH"
        threat_id = "2147626273"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s?user=%s&pass=%s&pass1=%s&title=%s" ascii //weight: 1
        $x_1_2 = "%s?user=%s&pass=%s&title=%s&url=%s" ascii //weight: 1
        $x_10_3 = "InternetOpenUrlA" ascii //weight: 10
        $x_10_4 = {47 65 74 48 74 6d 6c 50 77 64 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BHO_BI_2147626415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.BI"
        threat_id = "2147626415"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 53 74 61 72 74 2e 68 74 6d 3f 41 72 65 61 49 44 3d 4e 61 4e 26 4d 65 64 69 61 49 44 3d 35 30 30 31 31 26 41 64 4e 6f 3d 25 64 26 4f 72 69 67 69 6e 61 6c 69 74 79 49 44 3d 25 64 26 55 72 6c 3d 49 6e 74 65 72 6e 65 74 4d 6f 6e 69 74 6f 72 5f 53 74 61 72 74 5f 25 64 26 4d 61 63 3d 25 73 26 56 65 72 73 69 6f 6e 3d 25 64 26 56 61 6c 69 64 61 74 65 43 6f 64 65 3d 25 75 26 50 61 72 65 6e 74 4e 61 6d 65 3d 25 73 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "http://888888.2288.org/Monitor_INI" ascii //weight: 1
        $x_1_3 = "http://www.gamedanji.cn/ExeIni" ascii //weight: 1
        $x_1_4 = "http://88888888.7766.org/ExeIni" ascii //weight: 1
        $x_1_5 = {2f 49 6e 74 65 72 6e 65 74 4d 6f 6e 69 74 6f 72 2e 74 78 74 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {2f 53 74 61 72 74 2e 68 74 6d 3f 41 72 65 61 49 44 3d 4e 61 4e 26 4d 65 64 69 61 49 44 3d 35 30 30 31 31 26 41 64 4e 6f 3d 25 64 26 4f 72 69 67 69 6e 61 6c 69 74 79 49 44 3d 25 64 26 55 72 6c 3d 49 6e 74 65 72 6e 65 74 4d 6f 6e 69 74 6f 72 5f 53 65 74 75 70 5f 31 5f 30 26 4d 61 63 3d 25 73 26 56 65 72 73 69 6f 6e 3d 25 64 26 56 61 6c 69 64 61 74 65 43 6f 64 65 3d 25 75 26 50 61 72 65 6e 74 4e 61 6d 65 3d 25 73 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {2f 53 74 61 72 74 2e 68 74 6d 3f 41 72 65 61 49 44 3d 4e 61 4e 26 4d 65 64 69 61 49 44 3d 35 30 30 31 31 26 41 64 4e 6f 3d 25 64 26 4f 72 69 67 69 6e 61 6c 69 74 79 49 44 3d 25 64 26 55 72 6c 3d 77 61 72 6e 31 26 4d 61 63 3d 25 73 26 56 65 72 73 69 6f 6e 3d 25 64 26 56 61 6c 69 64 61 74 65 43 6f 64 65 3d 26 50 61 72 65 6e 74 4e 61 6d 65 3d 25 73 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {73 79 73 74 65 6d 33 32 5c 25 64 00 00 77 77 77 2e 36 36 36 36 2e 38 38 30 30 2e 6f 72 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_BL_2147626724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.BL"
        threat_id = "2147626724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "microsoft_lock" ascii //weight: 1
        $x_1_2 = "sysoption.ini" ascii //weight: 1
        $x_1_3 = "winio.sys" ascii //weight: 1
        $x_1_4 = "Microsoft (R) Red ISAM" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_BL_2147626725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.BL"
        threat_id = "2147626725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "microsoft_lock" ascii //weight: 1
        $x_1_2 = "winio.sys" ascii //weight: 1
        $x_1_3 = "Internet Extensions for Win32" wide //weight: 1
        $x_1_4 = "974BBDE6-925A-4702-A133-CAFE5C3F5784" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_BP_2147627425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.BP"
        threat_id = "2147627425"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ime\\SPTIPIMERS.ini" ascii //weight: 1
        $x_1_2 = "C:\\PROGRA~1\\pipi" ascii //weight: 1
        $x_1_3 = "del DelTemp.bat" ascii //weight: 1
        $x_1_4 = {80 7d fe 00 74 30 83 7e 04 00 0f 95 c0 84 d8 74 18 ff 76 10 68 ?? ?? ?? ?? ff 75 f4 8d 45 f4 ba 03 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_BQ_2147627557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.BQ"
        threat_id = "2147627557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 68 6f 4e 65 77 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_2 = "http://www.seeknewlive.com/bar/en.js" ascii //weight: 1
        $x_1_3 = "<img height=0 width=0 style=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_BR_2147627588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.BR"
        threat_id = "2147627588"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 78 70 6c 6f 72 65 72 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_2 = "= s 'YA2GOOGLE'" ascii //weight: 1
        $x_1_3 = "89731480-D47D-4DC4-8A36-BAAE55E094C5" ascii //weight: 1
        $x_1_4 = "Explorer.MExplorer = s 'MExplorer Class'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_BS_2147628596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.BS"
        threat_id = "2147628596"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 fc bf 80 00 00 00 50 8d 85 ?? ?? ff ff 50 57 68 ?? ?? 01 10 e8 ?? ?? 00 00 83 c4 10 85 c0 74 cd 89 75 fc 50 2b c0 85 c0 58 74 02 e8 04 8d 45 fc 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_BT_2147628804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.BT"
        threat_id = "2147628804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "http://www.fastbrowsersearch.com/results/results.aspx?q=" wide //weight: 3
        $x_3_2 = "{055069F3-F78B-4BD1-A277-FE66648D3300}" wide //weight: 3
        $x_1_3 = {5c 00 69 00 65 00 70 00 6c 00 75 00 67 00 69 00 6e 00 5c 00 62 00 68 00 6f 00 [0-5] 5c 00}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 69 65 70 6c 75 67 69 6e 5c 62 68 6f [0-5] 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BHO_LL_2147630040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.gen!LL"
        threat_id = "2147630040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {e8 2c e2 ff ff 68 84 65 00 20 a3 80 68 00 20 ff 35 84 68 00 20 e8 17 e2 ff ff 56 a3 78 68 00 20 ff 15 c8 50 00 20 39 35 7c 68 00 20 74 70 39 35 80 68 00 20 74 68}  //weight: 10, accuracy: High
        $x_1_2 = "xyzoef" ascii //weight: 1
        $x_1_3 = "7957FD21-C584-4476-B26B-4691A7AC4E5D" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BHO_BU_2147630083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.BU"
        threat_id = "2147630083"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "count=%s&data=%s&copy=%s&info=%s" ascii //weight: 1
        $x_1_2 = "regsvr32 /s %s" ascii //weight: 1
        $x_1_3 = "DllVanish" ascii //weight: 1
        $x_1_4 = "SeDebugPrivilege" wide //weight: 1
        $x_1_5 = "\\system32\\dllcache" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_BW_2147630234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.BW"
        threat_id = "2147630234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f2 ae 8b cd 4f c1 e9 02 f3 a5 8b cd 5d 83 e1 03 f3 a4 8b fa 83 c9 ff f2 ae f7 d1 2b f9 8b f7 8b d1 8b fb 83 c9 ff f2 ae 8b ca 4f c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 8d 44 ?? ?? 8d 4c ?? ?? 50 51 6a 00 6a 00 6a 00 6a 00 6a 00 8d 54 ?? ?? 6a 00 52 6a 00 ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = {68 61 6f 63 68 61 6a 69 61 6e 2e 63 6f 6d [0-16] 73 6e 69 66 66 65 72 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_5_3 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" ascii //weight: 5
        $x_5_4 = "%s,DllUnregisterServer" ascii //weight: 5
        $x_1_5 = "slive.exe" ascii //weight: 1
        $x_1_6 = "flive.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BHO_BY_2147630935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.BY"
        threat_id = "2147630935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 69 63 72 6f 73 6f 66 74 5f 6c 6f 63 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {89 45 08 8b d0 8a 04 0e 32 45 10 88 01 41 ff 4d 08 75 f2 88 1c 3a}  //weight: 1, accuracy: High
        $x_1_3 = {bb 68 01 00 00 eb 13 bb e8 01 00 00 eb 0c bb 70 01 00 00 eb 05 bb f0 01 00 00 bf 9f 86 01 00}  //weight: 1, accuracy: High
        $x_1_4 = {6a 3c 50 68 08 d0 04 00 ff 75 f8 ff 15 ?? ?? ?? ?? 85 c0 74 45 80 bd ?? ?? ff ff 00 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_BHO_CF_2147631701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.CF"
        threat_id = "2147631701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GET http://%s%s HTTP/1.1" ascii //weight: 1
        $x_1_2 = "Accept-Language:zh-cn" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\%s" ascii //weight: 1
        $x_1_4 = "/Start.htm?AreaID=NaN&MediaID=50011&AdNo=%d&OriginalityID=%d&Url=BHO_Start_%d&Mac=%s&Version=%d&ValidateCode=&ParentName=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_CJ_2147633593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.CJ"
        threat_id = "2147633593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 ab 66 ab aa 8d 85 e8 fe ff ff 50 e8 ?? ?? ?? ?? 59 8d 85 e8 fe ff ff 59 68 ?? ?? ?? ?? 56 50 e8 ?? ?? ?? ?? 59 50 8d 85 e8 fe ff ff 50 e8 ?? ?? ?? ?? 83 c4 10 8d 45 f8 50 8d 45 fc 50 53 68 3f 00 0f 00}  //weight: 1, accuracy: Low
        $x_1_2 = {62 68 6f 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_3 = "Officeelog.dll" ascii //weight: 1
        $x_1_4 = {43 4c 53 49 44 5c 25 73 5c 49 6e 70 72 6f 63 53 65 72 76 65 72 33 32 00 4d 69 63 72 6f 73 6f 66 74 [0-2] 28 52 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_CK_2147633600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.CK"
        threat_id = "2147633600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f2 ae f7 d1 2b f9 68 ?? ?? ?? ?? 8b c1 8b f7 8b fa 68 04 01 00 00 c1 e9 02 f3 a5 8b c8 33 c0 83 e1 03 f3 a4 8d 7c ?? ?? 83 c9 ff f2 ae f7 d1 49 51 8d 4c ?? ?? 51 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {62 68 6f 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_3 = "CLSID\\%s\\InprocServer32" ascii //weight: 1
        $x_1_4 = {6b 65 79 00 63 68 61 6e 6e 65 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_CL_2147633635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.CL"
        threat_id = "2147633635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 ab 66 ab aa bf ?? ?? ?? ?? 83 c9 ff 33 c0 68 ?? ?? ?? ?? f2 ae f7 d1 2b f9 68 04 01 00 00 8b c1 8b f7 8b fa 89 5c ?? ?? c1 e9 02 f3 a5 8b c8 33 c0 83 e1 03 89 5c ?? ?? f3 a4 8d 7c ?? ?? 83 c9 ff f2 ae f7 d1 49 51 8d 4c ?? ?? 51 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "bho2.DLL" ascii //weight: 1
        $x_1_3 = "CLSID\\%s\\InprocServer32" ascii //weight: 1
        $x_1_4 = {6b 65 79 00 63 68 61 6e 6e 65 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_CM_2147633636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.CM"
        threat_id = "2147633636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 ab 66 ab aa 8d 85 e4 fe ff ff c7 04 24 ?? ?? ?? ?? 50 89 5d f4 89 5d f0 e8 ?? ?? ?? ?? 59 8d 85 e4 fe ff ff 59 68 ?? ?? ?? ?? 68 04 01 00 00 50 e8 ?? ?? ?? ?? 59 50 8d 85 e4 fe ff ff 50 e8 ?? ?? ?? ?? 83 c4 10 8d 45 f8 50 8d 45 fc 50 53 68 3f 00 0f 00}  //weight: 1, accuracy: Low
        $x_1_2 = "xbdho2.DLL" ascii //weight: 1
        $x_1_3 = "CLSID\\%s\\InprocServer32" ascii //weight: 1
        $x_1_4 = {6b 65 79 00 63 68 61 6e 6e 65 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_CP_2147634583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.CP"
        threat_id = "2147634583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\windows\\messenger\\messenger.exe" ascii //weight: 1
        $x_1_2 = ".6666.8800.org" ascii //weight: 1
        $x_1_3 = "stat.wamme.cn/C8C/gl/cnzz5c.html" ascii //weight: 1
        $x_1_4 = "cake.sunfacepizza.cn/" ascii //weight: 1
        $x_1_5 = "888888.2288.org/ExeIni14/MessengerNew.txt" ascii //weight: 1
        $x_1_6 = ".gamedanji.cn/ExeIni14/MessengerNew.txt" ascii //weight: 1
        $x_1_7 = "1235633.3322.org/ExeIni14/MessengerNew.txt" ascii //weight: 1
        $x_1_8 = "stat.wamme.cn/C8C/gl/cnzz5b.html" ascii //weight: 1
        $x_1_9 = "/Start.htm?AreaID=NaN&MediaID=50011&AdNo=%d&OriginalityID=%d&Url=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_BHO_LN_2147635920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.LN"
        threat_id = "2147635920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {5c 00 6f 8f f6 4e e5 5d 0b 7a 5c 00 62 00 68 00 6f 00 5c 00}  //weight: 4, accuracy: High
        $x_1_2 = "ieupdate.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_CQ_2147635926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.CQ!dll"
        threat_id = "2147635926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "QvodAdBlocker" ascii //weight: 1
        $x_2_2 = "\\IEAdBlocker.vbp" wide //weight: 2
        $x_1_3 = {2f 00 2f 00 6a 00 73 00 ?? ?? 2e 00 31 00 38 00}  //weight: 1, accuracy: Low
        $x_1_4 = "o.com/ie.js" wide //weight: 1
        $x_1_5 = {48 3a 5c 55 c5 cc ce c4 bc fe 5c b3 cc d0 f2 d4 b4 b4 fa c2 eb 5c b3 cc d0 f2 5c c8 ed bc fe 5c b9 e3 b8 e6 be ad d3 aa cd ea d5 fb b3 cc d0 f2 b0 fc 5c 42 48 4f b2 e5 bc fe 5c 56 42 42 48 4f 2e 74 6c 62}  //weight: 1, accuracy: High
        $x_1_6 = {46 6d 5f 69 65 5f 44 6f 63 75 6d 65 6e 74 43 6f 6d 70 6c 65 74 65 [0-8] 53 74 72 54 6f 48 65 78}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BHO_CS_2147636218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.CS"
        threat_id = "2147636218"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Accept-Language:zh-cn" ascii //weight: 1
        $x_1_2 = "C:\\Program Files\\NewGameUpdate\\GameVersionUpdate.dll" ascii //weight: 1
        $x_1_3 = "Url=GameVersionUpdate_Setup&Mac=%s&Version=" ascii //weight: 1
        $x_1_4 = "C:\\WINDOWS\\system32\\drivers\\etc\\service1.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_CT_2147636880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.CT!dll"
        threat_id = "2147636880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ca-pub-3158699163834646" ascii //weight: 1
        $x_1_2 = "\\ieper.tmp" ascii //weight: 1
        $x_1_3 = "mskdji33434323.com" ascii //weight: 1
        $x_1_4 = "Referer: http://www.xxx.com" ascii //weight: 1
        $x_1_5 = "%s\\ab%d%d%d.tmp" ascii //weight: 1
        $x_1_6 = "&p=http%3A//" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_BHO_CV_2147636998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.CV"
        threat_id = "2147636998"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GameVersionUpdate.dll" ascii //weight: 1
        $x_1_2 = "get http://%s%s http/1.1" ascii //weight: 1
        $x_1_3 = "Url=GameVersionUpdate_Setup&Mac=%s&Version=" ascii //weight: 1
        $x_1_4 = "C:\\WINDOWS\\system32\\drivers\\etc\\service1.ini" ascii //weight: 1
        $x_1_5 = "/Start.htm?s1=ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_BHO_CZ_2147637353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.CZ"
        threat_id = "2147637353"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 7d fe 00 74 30 83 7e 04 00 0f 95 c0 84 d8 74 18 ff 76 10 68 ?? ?? ?? ?? ff 75 f4 8d 45 f4 ba 03 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "IE(AL(\"%s\"," ascii //weight: 1
        $x_1_3 = "\\_IEBrowserHelper.pas" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\explorer\\Browser Helper Objects" ascii //weight: 1
        $x_1_5 = "toast.duno.kr/ifr_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_DA_2147637361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.DA!dll"
        threat_id = "2147637361"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "*mmstat*.txt" ascii //weight: 1
        $x_1_2 = "udp\\hjob123\\com" ascii //weight: 1
        $x_1_3 = "{AE138609-AF9F-6BB6-A6A8-2DC583D9DF06}" ascii //weight: 1
        $x_1_4 = "ww.206m;yuio?oklogi" ascii //weight: 1
        $x_1_5 = "d_DefBg2.txt" ascii //weight: 1
        $x_1_6 = "C:\\R_bmTim2.fg" ascii //weight: 1
        $x_1_7 = {4e 65 77 50 6c 75 67 [0-3] 5c 54 69 6d 65 44 6c 6c 5c 7a 6c 75 45 78 70 54 6f 6f 6c 73 2e 70 61 73}  //weight: 1, accuracy: Low
        $x_1_8 = {72 65 70 2e 65 78 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? 52 75 6e 43 6c 69 63 6b 50 72 45 72 72 3a}  //weight: 1, accuracy: Low
        $x_1_9 = {5b 2d 25 73 25 73 5d [0-21] 2e 72 65 67 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_BHO_DE_2147637518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.DE"
        threat_id = "2147637518"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d6 3b c3 0f 85 ?? ?? ?? ?? 6a 13 33 c0 5a 8d bd 6d fe ff ff 8b ca 88 9d 6c fe ff ff f3 ab 66 ab aa}  //weight: 1, accuracy: Low
        $x_1_2 = "CLSID = s '{67E4DD8F-F899-4b99-A5B2-C72445B5C962}'" ascii //weight: 1
        $x_1_3 = "IEHpr.Invoke.1 = s 'BHO Class'" ascii //weight: 1
        $x_1_4 = {54 6f 6f 6c 62 61 72 57 69 6e 64 6f 77 33 32 00 49 45 46 72 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_5 = "Flacdker" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_DC_2147637523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.DC!dll"
        threat_id = "2147637523"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "E:\\_Program\\chrome\\__bin\\Debug\\log.txt" ascii //weight: 1
        $x_1_2 = "tj.hao750.com/redirecttest.txt" ascii //weight: 1
        $x_1_3 = "{8A9FA972-F63C-4B3C-9AE3-627A0C621111} = s" ascii //weight: 1
        $x_1_4 = {5c 00 00 00 66 75 63 6b 79 6f 75 00 5c 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 00 00 00 5f 32 30 30 38 5f 00 00 5c 00}  //weight: 1, accuracy: High
        $x_1_6 = {2f 00 00 00 00 23 78 79 7a 31 30 32 38 71 74 6d 00 [0-8] 74 6f 6e 67 6a 69 2e 00 74 6a 2e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_BHO_DF_2147637561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.DF"
        threat_id = "2147637561"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TopGuide.exe" ascii //weight: 1
        $x_1_2 = "info-way.kr/addPages/?" ascii //weight: 1
        $x_1_3 = "topguide.co.kr/install.asp?" ascii //weight: 1
        $x_1_4 = "{D94DCC35-A105-4A97-A957-FB7D54BB3612}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_DF_2147637561_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.DF"
        threat_id = "2147637561"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ijxylmro.txt" ascii //weight: 1
        $x_1_2 = "{73A7FFA7-AA3A-49E5-A777-713B7DB78E9C}" wide //weight: 1
        $x_1_3 = {61 73 79 2e 63 6f 6d 2f 69 73 6f 2f 00 00 00 00 77 77 2e 67 6f 32 65 00 70 3a 2f 2f 77 00 00 00 68 74 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {21 00 00 00 6f 6d 2f 73 3f 00 00 00 69 64 75 3f 00 00 00 00 6f 6d 2f 62 61 00 00 00 75 2e 63 00 62 61 69 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {38 38 2d 41 46 30 43 2d 39 31 34 39 44 45 37 30 45 31 33 32 7d 00 00 00 74 70 5c 7b 32 31 43 30 46 38 36 42 2d 34 33 34 38 2d 34 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_DC_2147637797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.DC"
        threat_id = "2147637797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 ff 30 64 89 20 b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 c0 5a 59 59 64 89 10 eb ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = ".co.kr" ascii //weight: 1
        $x_1_3 = "ie(al(\"%s\"," ascii //weight: 1
        $x_1_4 = "ydown" ascii //weight: 1
        $x_1_5 = "tpopuplist" ascii //weight: 1
        $x_1_6 = {64 6c 6c 63 61 6e 75 6e 6c 6f 61 64 6e 6f 77 00 64 6c 6c 67 65 74 63 6c 61 73 73 6f 62 6a 65 63 74 00 64 6c 6c 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 64 6c 6c 75 6e 72 65 67 69 73 74 65 72 73 65 72 76 65 72}  //weight: 1, accuracy: High
        $x_1_7 = "siteurl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_DK_2147638748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.DK"
        threat_id = "2147638748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 83 3e 27 75 10 40 3b ?? 73 0b ba 27 00 00 00 66 89 11 83 c1 02 40 83 c6 02 3b ?? 72 d4}  //weight: 1, accuracy: Low
        $x_1_2 = "{A3752EF8-C633-4B67-95C7-86AD53695FC1}" wide //weight: 1
        $x_1_3 = ".com/?url=http://gogo." ascii //weight: 1
        $x_1_4 = "&cm_id=&pm_id=" ascii //weight: 1
        $x_1_5 = "td\\tao96\\tao96\\Release\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_BHO_DN_2147639532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.DN"
        threat_id = "2147639532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IEHpr.Invoke.1 = s 'Invoke Class'" ascii //weight: 1
        $x_1_2 = "TjmPwb3_Gfebvow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_DO_2147639534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.DO"
        threat_id = "2147639534"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "csyssjt.dat" ascii //weight: 3
        $x_3_2 = "http://www.beidou123.cn/count.asp" ascii //weight: 3
        $x_2_3 = "BHOLOCKER.BhoLock.1 = s 'BhoLock Class'" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BHO_DG_2147639889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.DG!dll"
        threat_id = "2147639889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TopGuide.exe" wide //weight: 1
        $x_1_2 = "info-way.kr/addPages/?id=%s&k=%s" wide //weight: 1
        $x_1_3 = {5c ed 94 84 eb a1 9c ec a0 9d ed 8a b8 5c 74 6f 70 67 75 69 64 65 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_DH_2147639890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.DH!dll"
        threat_id = "2147639890"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/relation_bar.asp?k=%s&id=%s&m=%s" ascii //weight: 1
        $x_1_2 = "topguide.co.kr/update/" ascii //weight: 1
        $x_1_3 = "{1ED65C88-1259-484B-A9FA-6731E0D15743}" ascii //weight: 1
        $x_1_4 = "{7D1AFD44-BEA6-48BD-8872-21940D385C3B}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_DI_2147640165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.DI!dll"
        threat_id = "2147640165"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3c 30 7c 20 3c 39 7e 18 3c 40 7e 18 3c 46 7e 0c 3c 60 7e 10 3c 66 7f 0c 83 e8 57 c3 83 e8 37 c3 83 e8 30 c3}  //weight: 1, accuracy: High
        $x_1_2 = {32 65 61 73 79 2e 00 00 77 2e 67 6f 00 00 00 00 69 73 6f 00 63 6f 6d 2f 00}  //weight: 1, accuracy: High
        $x_1_3 = {be a9 ca d0 00 00 00 00 c0 b4 d7 d4 a3 ba b1 b1 00}  //weight: 1, accuracy: High
        $x_2_4 = "{73A7FFA7-AA3A-49E5-A777-713B7DB78E9C}" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BHO_DQ_2147640751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.DQ"
        threat_id = "2147640751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "config_popup_0_after_startup_delay" ascii //weight: 3
        $x_2_2 = "popupBHOEvent" wide //weight: 2
        $x_2_3 = "config_cookies_0_killcount" ascii //weight: 2
        $x_1_4 = "disableredirectfrom" ascii //weight: 1
        $x_3_5 = "config_popup_0_show_timeout" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_DS_2147640846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.DS"
        threat_id = "2147640846"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 73 79 6d 61 6e 74 7e 31 5c [0-5] 5c 73 79 6d 61 6e 74 65 63 5c [0-5] 5c 61 6e 74 69 73 70 79 57 61 72 65 5c [0-5] 5c 72 69 73 69 6e 67 5c}  //weight: 2, accuracy: Low
        $x_2_2 = {2f 63 6e 7a 7a [0-6] 2e 68 74 6d 6c 3f [0-10] 6c 61 67 3d 25 64 2c 4f 74 68 65 72 53 65 74 75 70 3d 25 64 2c 52 65 70 61 69 72 53 65 74 75 70 3d 25 64}  //weight: 2, accuracy: Low
        $x_2_3 = "C:\\Program Files\\NewGameUpdate\\GAmeVersionUPdate.temp" ascii //weight: 2
        $x_1_4 = {3f 48 6f 6f 6b 31 3d [0-2] 2c 53 65 74 75 70 3d [0-32] 3a 2f 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c}  //weight: 1, accuracy: Low
        $x_1_5 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 73 65 72 76 69 63 65 [0-6] 2e 69 6e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BHO_DZ_2147642425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.DZ"
        threat_id = "2147642425"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 75 2e 79 6f 75 68 65 6d 65 2e 63 6f 6d 2f 71 69 62 68 6f 2e 69 6e 69 3f 74 3d 25 64 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 7b 36 43 38 37 37 32 32 32 2d 44 38 37 35 2d 34 41 42 41 2d 39 37 39 38 2d 36 34 38 45 38 42 45 42 43 44 33 43 7d 00 00 00 76 00 00 00 72 6f 6f 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {51 00 49 00 42 00 48 00 4f 00 5f 00 46 00 41 00 4b 00 45 00 55 00 52 00 4c 00 5f 00 43 00 4f 00 4f 00 4b 00 49 00 45 00 00 00 00 00 53 00 68 00 65 00 6c 00 6c 00 20 00 44 00 6f 00 63 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 56 00 69 00 65 00 77 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_KB_2147643448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.KB!dll"
        threat_id = "2147643448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ppumynew=" ascii //weight: 1
        $x_1_2 = "%stbcfgnl.ini" ascii //weight: 1
        $x_1_3 = "%sppfilecnfg.ini" ascii //weight: 1
        $x_1_4 = "!*&*none-value*&!*" ascii //weight: 1
        $x_1_5 = {2f 74 6e 73 2f 74 62 74 6e 73 30 34 30 31 2e 68 74 6d 30 00 68 74 74 70 3a 2f 2f 74 62 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_KC_2147643449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.KC"
        threat_id = "2147643449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 1c 0e 32 da 88 19 41 4d 75 f5}  //weight: 1, accuracy: High
        $x_1_2 = ".770304123.cn" ascii //weight: 1
        $x_1_3 = "jvvr8--:::,:61acnn,al-cfrcai,vzv" ascii //weight: 1
        $x_1_4 = {44 34 36 36 44 7d 00 00 32 46 30 32 38 31 30 42 42 39 00 00 7b 30 31 44 45 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_KI_2147646224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.KI"
        threat_id = "2147646224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\teste.gt" ascii //weight: 1
        $x_1_2 = "*heima8*.txt" ascii //weight: 1
        $x_1_3 = "bigetcnafn.dl" ascii //weight: 1
        $x_1_4 = "s-c.-he-oru.c-om" ascii //weight: 1
        $x_1_5 = "s-d.-he-o-ru.c-o-m" ascii //weight: 1
        $x_1_6 = "82DAF06B-3E0D-2F1D-AFA8-959DDD3E8BE3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_EE_2147646791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.EE"
        threat_id = "2147646791"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "c@p@p p@r@em$i$um$-@li@n@k" ascii //weight: 5
        $x_2_2 = "FORM1_A_IFRAME" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_EF_2147646984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.EF"
        threat_id = "2147646984"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "e:\\JinZQ\\" ascii //weight: 4
        $x_4_2 = "stat.wamme.cn" ascii //weight: 4
        $x_2_3 = "GameVersionUpdate" ascii //weight: 2
        $x_2_4 = "C:\\WINDOWS\\system32\\drivers\\etc\\service1.ini" ascii //weight: 2
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Network" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" ascii //weight: 1
        $x_1_7 = "NoNetConnectDisconnect" ascii //weight: 1
        $x_1_8 = "%2\\protocol\\StdFileEditing\\server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BHO_EH_2147647539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.EH"
        threat_id = "2147647539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "http://spy-kill.com/bho_adult.txt" ascii //weight: 4
        $x_5_2 = "D:\\App\\Delphi7\\Source Code\\Adware\\_IEBrowserHelper.pas" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_EJ_2147647745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.EJ"
        threat_id = "2147647745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".com/o@sl@2/o@v$n_o.a$sp?dll=1" ascii //weight: 1
        $x_1_2 = ".com/o@sl@2/@e$xe/d$name.ht@ml" ascii //weight: 1
        $x_1_3 = "?searchcode=n&isdate=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_EN_2147650208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.EN"
        threat_id = "2147650208"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" ascii //weight: 1
        $x_3_2 = "ht*,+,^ab*tp:/*,+,^ab*/" ascii //weight: 3
        $x_4_3 = ".e*,+,^ab*x*,+,^ab*e" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_EP_2147650922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.EP"
        threat_id = "2147650922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 ff 30 64 89 20 b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 c0 5a 59 59 64 89 10 eb ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = "ydown" ascii //weight: 1
        $x_1_3 = "tpopuplist" ascii //weight: 1
        $x_1_4 = "\\livefloat" ascii //weight: 1
        $x_1_5 = "\\_iebrowserhelper.pas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BHO_ES_2147652695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.ES"
        threat_id = "2147652695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {49 73 49 65 4f 70 65 6e 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 49 73 44 65 6c 4d 79 53 65 6c 66 00 53 65 72 76 65 72 55 72 6c}  //weight: 2, accuracy: Low
        $x_2_2 = "safemon.dll" ascii //weight: 2
        $x_1_3 = "taskkill /F /IM %s" ascii //weight: 1
        $x_1_4 = "%s?user=%s&pass=%s&" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BHO_EV_2147659358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.EV"
        threat_id = "2147659358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fhelp.kr" ascii //weight: 1
        $x_1_2 = "sircheckfile.dat" ascii //weight: 1
        $x_1_3 = "?pname=ions&pcode=" wide //weight: 1
        $x_1_4 = "\\_IEBrowserHelper.pas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_BHO_LQ_2147712303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BHO.LQ!bit"
        threat_id = "2147712303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BHO"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 fb 26 74 ?? 80 fb 2e 74 ?? 80 fb 36 74 ?? 80 fb 3e 74 ?? 80 fb 64 74 ?? 80 fb 65}  //weight: 1, accuracy: Low
        $x_1_2 = "{B69F34DD-F0F9-42DC-9EDD-957187DA688D}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

