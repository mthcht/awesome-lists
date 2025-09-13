rule Trojan_Win32_Urelas_A_2147653786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Urelas.A"
        threat_id = "2147653786"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Urelas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 a4 1c 04 10 8d 55 ec 52 e8 00 dd fc ff 83 c4 10 c6 45 fc 00 8d 4d e8 e8 81 de fc ff 51 8b c4 89 65 e4 50 e8 55 03 00 00 83 c4 04 89 45 d4 8b 4d d4 89 4d d0 c6 45 fc 02 51 8b cc 89 65 e0 8d 55 ec 52 e8 16 d9 fc ff 89 45 cc c6 45 fc 00 e8 8a fd ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Urelas_A_2147653786_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Urelas.A"
        threat_id = "2147653786"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Urelas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Window Usre Login" ascii //weight: 1
        $x_1_2 = "LASPOKER.exe" wide //weight: 1
        $x_1_3 = "$$WindowsXp.bat" wide //weight: 1
        $x_1_4 = {09 5f 50 4d 4e 55 4d 42 45 52}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Urelas_B_2147656744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Urelas.B"
        threat_id = "2147656744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Urelas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 00 41 00 53 00 50 00 4f 00 4b 00 45 00 52 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {70 00 6f 00 6b 00 65 00 72 00 37 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {42 00 61 00 64 00 75 00 6b 00 69 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {48 00 4f 00 4f 00 4c 00 41 00 33 00 2e 00 45 00 58 00 45 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {44 00 75 00 65 00 6c 00 50 00 6f 00 6b 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {46 00 4e 00 46 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {57 00 69 00 6e 00 42 00 6f 00 6f 00 74 00 5f 00 4c 00 6f 00 67 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {24 00 24 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 58 00 70 00 2e 00 62 00 61 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {52 00 65 00 73 00 6f 00 6c 00 76 00 69 00 6e 00 67 00 20 00 68 00 6f 00 73 00 74 00 6e 00 61 00 6d 00 65 00 20 00 25 00 73 00 2e 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Urelas_C_2147656778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Urelas.C"
        threat_id = "2147656778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Urelas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {40 3d e0 01 00 00 72 ee 81 7c 24 08 4d 53 4d 50 75}  //weight: 5, accuracy: High
        $x_1_2 = {25 00 73 00 5c 00 25 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {67 00 6f 00 6c 00 66 00 69 00 6e 00 66 00 6f 00 2e 00 69 00 6e 00 69 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Urelas_C_2147656778_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Urelas.C"
        threat_id = "2147656778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Urelas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "LASPOKER.exe" wide //weight: 10
        $x_1_2 = {42 00 61 00 64 00 75 00 6b 00 69 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {48 00 4f 00 4f 00 4c 00 41 00 33 00 2e 00 45 00 58 00 45 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {46 00 4e 00 46 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {70 00 6f 00 6b 00 65 00 72 00 37 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "_PMNUMBER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Urelas_C_2147656778_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Urelas.C"
        threat_id = "2147656778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Urelas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 00 69 00 67 00 68 00 6c 00 6f 00 77 00 32 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {4c 00 41 00 53 00 50 00 4f 00 4b 00 45 00 52 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_3_3 = "_WinFDC" ascii //weight: 3
        $x_3_4 = "_VCAPTURE" ascii //weight: 3
        $x_3_5 = "_SENDIMAGE" ascii //weight: 3
        $x_10_6 = {50 00 4d 00 43 00 6c 00 69 00 65 00 6e 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 10, accuracy: High
        $x_10_7 = {24 00 24 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 58 00 70 00 2e 00 62 00 61 00 74 00 00 00}  //weight: 10, accuracy: High
        $x_3_8 = {47 00 41 00 4d 00 45 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 36 00 30 00 30 00 34 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 36 00 30 00 30 00 33 00}  //weight: 3, accuracy: Low
        $x_3_9 = {73 00 76 00 63 00 73 00 67 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 73 00 6d 00 73 00 65 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 5 of ($x_3_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Urelas_E_2147679529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Urelas.E"
        threat_id = "2147679529"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Urelas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {a5 a5 a5 66 a5 81 bd ec fb ff ff 4d 53 4d 50 89 0d f0 43 41 00 75 35}  //weight: 5, accuracy: High
        $x_5_2 = {75 04 33 c0 eb 45 81 38 4d 53 4d 50 75 f4}  //weight: 5, accuracy: High
        $x_1_3 = {67 00 6f 00 6c 00 66 00 73 00 65 00 74 00 2e 00 69 00 6e 00 69 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {4d 00 6b 00 55 00 70 00 64 00 61 00 74 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Urelas_K_2147682402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Urelas.K"
        threat_id = "2147682402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Urelas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "golfinfo.ini" wide //weight: 10
        $x_10_2 = "_uninsep.bat" wide //weight: 10
        $x_10_3 = "systemkey" wide //weight: 10
        $x_1_4 = {40 3d 00 02 00 00 72 ?? 81 [0-5] 4d 53 4d 50 75 ?? 68 00 02 00 00 8d [0-5] 52 53 e8}  //weight: 1, accuracy: Low
        $x_1_5 = {81 38 4d 53 4d 50 75 ?? be 00 02 00 00 56 50 8d 85 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Urelas_O_2147683133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Urelas.O"
        threat_id = "2147683133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Urelas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 38 4d 53 4d 50 75 e8 68 00 02 00 00 50 8d 85 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {67 00 6f 00 6c 00 66 00 69 00 6e 00 66 00 6f 00 2e 00 69 00 6e 00 69 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Urelas_AA_2147707480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Urelas.AA"
        threat_id = "2147707480"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Urelas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MSMP" ascii //weight: 1
        $x_1_2 = {6a 0f 59 be ?? ?? ?? ?? f3 a5 66 a5 33 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {8b f7 81 e6 ff 01 00 00 f7 de 1b f6 89 38 8b c7 f7 de c1 e8 09 03 f0 c1 e6 09 56}  //weight: 1, accuracy: High
        $x_1_4 = {eb 10 81 7d ?? 50 4b 01 02 74 07}  //weight: 1, accuracy: Low
        $x_1_5 = "golfinfo.ini" wide //weight: 1
        $x_1_6 = "golfset.ini" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Urelas_JU_2147743862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Urelas.JU!MTB"
        threat_id = "2147743862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Urelas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "golfinfo.ini" wide //weight: 1
        $x_1_2 = "\\HGDraw.dll" wide //weight: 1
        $x_1_3 = "IDR_BINARY" wide //weight: 1
        $x_1_4 = "Newbadugi.exe" wide //weight: 1
        $x_1_5 = "SeDebugPrivilege" wide //weight: 1
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Urelas_EC_2147892160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Urelas.EC!MTB"
        threat_id = "2147892160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Urelas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DuelPoker.exe" wide //weight: 1
        $x_1_2 = "Newbadugi.exe" wide //weight: 1
        $x_1_3 = "218.54.31.165" wide //weight: 1
        $x_1_4 = "MyCom" wide //weight: 1
        $x_1_5 = "golfinfo.ini" wide //weight: 1
        $x_1_6 = "_MYDEBUG:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Urelas_ASC_2147901805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Urelas.ASC!MTB"
        threat_id = "2147901805"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Urelas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sanfdr.bat" ascii //weight: 2
        $x_2_2 = "121.88.5.183" ascii //weight: 2
        $x_2_3 = "121.88.5.184" ascii //weight: 2
        $x_1_4 = "%s%s.exe" wide //weight: 1
        $x_1_5 = "\\.\\PHYSICALDRIVE" wide //weight: 1
        $x_1_6 = {33 c0 f6 94 05 f4 fd ff ff 40 3b c6 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Urelas_ASD_2147902395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Urelas.ASD!MTB"
        threat_id = "2147902395"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Urelas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c2 c1 f8 05 8b 04 85 [0-3] 00 8b fa 83 e7 1f c1 e7 06 8b 04 07 83 f8 ff 74 08 3b c6 74 04 85 c0 75 02 89 31 83 c1 20 42 81 f9 38 22 42 00 7c}  //weight: 2, accuracy: Low
        $x_1_2 = "golfinfo.ini" wide //weight: 1
        $x_1_3 = "GDSGDWHSYD" wide //weight: 1
        $x_1_4 = "Boahkilser" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Urelas_GPA_2147905546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Urelas.GPA!MTB"
        threat_id = "2147905546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Urelas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 00 69 00 61 00 73 00 52 00 65 00 74 00 69 00 6e 00 61}  //weight: 1, accuracy: High
        $x_1_2 = {4e 00 65 00 77 00 62 00 61 00 64 00 75 00 67 00 69}  //weight: 1, accuracy: High
        $x_1_3 = {44 00 75 00 65 00 6c 00 50 00 6f 00 6b 00 65 00 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Urelas_HNS_2147905964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Urelas.HNS!MTB"
        threat_id = "2147905964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Urelas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 00 41 00 53 00 50 00 4f 00 4b 00 45 00 52 00 00 00 00 00 b0 04 02 00 ff ff ff ff 0c 00 00 00 5c d5 8c ac 84 c7 20 00 7c b7 a4 c2 a0 bc 00 ac}  //weight: 1, accuracy: High
        $x_1_2 = {70 00 6f 00 6b 00 65 00 72 00 37 00 00 00 00 00 b0 04 02 00 ff ff ff ff 07 00 00 00 5c d5 8c ac 84 c7 20 00 37}  //weight: 1, accuracy: High
        $x_1_3 = {44 00 75 00 65 00 6c 00 50 00 6f 00 6b 00 65 00 72 00 00 00 b0 04 02 00 ff ff ff ff 07 00 00 00 5c d5 8c ac 84 c7 20 00 de b9 ec d3 e4 ce 00 00 b0 04 02 00 ff ff ff ff 09 00 00 00 4e 00 65 00 77 00 62 00 61 00 64 00 75 00 67 00 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

