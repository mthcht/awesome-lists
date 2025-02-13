rule Trojan_Win32_Tracur_Q_2147655918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.Q"
        threat_id = "2147655918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" ascii //weight: 1
        $x_1_3 = "search_query=" ascii //weight: 1
        $x_1_4 = "%s?q=%s&su=%s&%s&z=%s" ascii //weight: 1
        $x_1_5 = "&t=direct" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Classes\\.fsharproj\\PersistentHandler" ascii //weight: 1
        $x_1_7 = "u=%s&a=%s&i=%s&s=%s" ascii //weight: 1
        $x_1_8 = "%s\\xulcache.jar" ascii //weight: 1
        $x_1_9 = "Application Data\\Mozilla\\Firefox\\Profiles\\*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Tracur_AE_2147655920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.AE"
        threat_id = "2147655920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d ce 07 00 00 77 0a be d0 07 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8a 44 2f 01 83 c5 01 2c 67 83 c1 01 3c 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tracur_J_2147655921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.J"
        threat_id = "2147655921"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff 37 c7 45 70 20 4e 00 00 ff 15 ?? ?? ?? ?? 8b d8 3b de 74 6c}  //weight: 2, accuracy: Low
        $x_1_2 = "%s?q=%s&su=%s" ascii //weight: 1
        $x_1_3 = "u=%s&a=%s&i=%s&s=%s" ascii //weight: 1
        $x_1_4 = "%s?ping=1&%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tracur_X_2147655922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.X"
        threat_id = "2147655922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8a 10 30 14 31 83 c0 01 80 38 00 75 05 b8 ?? ?? ?? ?? 83 c1 01 3b cf 72 e7 8b c6 5f 5e 5b}  //weight: 3, accuracy: Low
        $x_1_2 = "advfirewall firewall add rule name=\"Windows Update Service\" dir=in action=allow program=\"" ascii //weight: 1
        $x_1_3 = "name=\"Windows Update Service\" mode=ENABLE scope=ALL profile=ALL" ascii //weight: 1
        $x_1_4 = "\\msiexec.exe" ascii //weight: 1
        $x_1_5 = "\\netsh.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tracur_A_2147655923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.A"
        threat_id = "2147655923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 0e 32 9a ?? ?? 40 00 83 c2 01 3b d5 88 5c 0e ff 75 02 33 d2 83 c1 01 3b cf 7e e3 5b 5f 88 44 31 ff 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tracur_A_2147655923_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.A"
        threat_id = "2147655923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 65 66 c7 46 ?? 74 6f 66 c7 46 ?? 75 72 66 c7 46 ?? 73 21}  //weight: 2, accuracy: Low
        $x_2_2 = {74 4e 8b 0e 8d 44 01 01 50 e8}  //weight: 2, accuracy: High
        $x_2_3 = {85 c0 74 6c 81 7d fc c8 00 00 00 75 63 ff 75 f4}  //weight: 2, accuracy: High
        $x_1_4 = {99 68 80 96 98 00 52 50 e8}  //weight: 1, accuracy: High
        $x_1_5 = {1b 4d f4 6a 08 68 00 68 c4 61 51 50 e8}  //weight: 1, accuracy: High
        $x_2_6 = {70 31 39 45 33 4e 55 53 48 41 47 43 68 75 73 68 79 73 6a 77 76 00}  //weight: 2, accuracy: High
        $x_2_7 = {51 75 69 77 38 32 68 64 44 65 67 5b 75 61 56 31 6e 32 78 75 53 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tracur_Y_2147655926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.Y"
        threat_id = "2147655926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 0c 8a 11 03 c7 30 10 41 80 39 00 75 02 8b ce 47 3b 7c 24 10 72 e7}  //weight: 1, accuracy: High
        $x_1_2 = {8a 04 0a 32 87 ?? ?? ?? ?? 47 3b 7d ec 88 01 7c 02 33 ff 41 ff 4d fc 75 e7}  //weight: 1, accuracy: Low
        $x_1_3 = {89 5d f0 c7 45 e4 04 00 00 00 89 5d e8 ff 15 ?? ?? ?? ?? 85 c0 74 19 81 7d f0 c8 00 00 00 74 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Tracur_B_2147655928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.B"
        threat_id = "2147655928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1b 4d f4 6a 08 68 00 68 c4 61 51 50 e8}  //weight: 1, accuracy: High
        $x_1_2 = {66 c7 46 1c 44 65 66 c7 46 1e 74 6f 66 c7 46 20 75 72}  //weight: 1, accuracy: High
        $x_1_3 = {68 b8 0b 00 00 ff 15 ?? ?? ?? 10 68 88 13 00 00 ff 74 24 08 6a 00}  //weight: 1, accuracy: Low
        $x_1_4 = {39 54 24 10 8b f8 7e 1d 8b 44 24 0c 8d 0c 06 8a 82 ?? ?? ?? 10 30 01 42}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Tracur_AC_2147655930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.AC"
        threat_id = "2147655930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Z:\\dev\\cb_loader\\Release\\cb_loader.pdb" ascii //weight: 1
        $x_1_2 = {3d 2e 4a 50 47 74 21 3d 2e 6a 70 67 74 1a 3d 2e 65 78 65 74 13 3d 2e 74 6d 70 74 0c 3d 2e 45 58 45 74 05 3d 2e 54 4d 50}  //weight: 1, accuracy: High
        $x_1_3 = {8b 79 08 8a 14 07 88 14 3e 83 c0 01 83 c6 01 3b 41 0c 72 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Tracur_AG_2147655939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.AG"
        threat_id = "2147655939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 2e 6a 70 67 74 1a 3d 2e 65 78 65 74 13}  //weight: 1, accuracy: High
        $x_1_2 = {0f a2 31 d0 31 c8 5a 31 c2 8b 45 ?? 8b 80 88 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {e2 fa 5b 8b 45 08 8b 08 81 f9 14 e2 a4 fc 89 85}  //weight: 1, accuracy: High
        $x_1_4 = {66 3d 8b ff 74 14 31 c0 01 f8 05 00 02 00 00 3d 01 00 00 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Tracur_AK_2147655940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.AK"
        threat_id = "2147655940"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 04 8b f0 68 00 10 00 00 8d 46 01 50 6a 00 ff 15}  //weight: 2, accuracy: High
        $x_2_2 = {89 43 04 3b c6 74 33 8b 43 08 8d 8d ?? ?? ?? ?? 51 c1 e0 05}  //weight: 2, accuracy: Low
        $x_1_3 = "search_query=" ascii //weight: 1
        $x_1_4 = "Shm_%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tracur_AD_2147655941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.AD"
        threat_id = "2147655941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".exe:*:Enabled:Windows Update Service" wide //weight: 1
        $x_1_2 = "[PGUP]" wide //weight: 1
        $x_1_3 = "[ClipBoard Begin] Time: " wide //weight: 1
        $x_1_4 = "Project1.Module1.CreateBitmapPicture" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tracur_AA_2147655942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.AA"
        threat_id = "2147655942"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {26 69 70 3d 73 65 6c 66 26 6b 77 3d 00}  //weight: 2, accuracy: High
        $x_2_2 = {63 61 6e 6e 6f 74 20 67 65 74 20 63 6c 69 63 6b 20 69 6e 66 6f 00}  //weight: 2, accuracy: High
        $x_2_3 = {70 72 6f 63 65 73 73 5f 66 69 6c 65 5f 6e 61 6d 65 3d 6d 79 73 65 6c 66 2e 64 6c 6c 00}  //weight: 2, accuracy: High
        $x_1_4 = {2f 61 75 64 69 6f 5f 6d 73 6e 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {2f 61 72 73 65 6e 61 6c 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_6 = "/login/ /tweet/ action=embed-flash" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tracur_C_2147655943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.gen!C"
        threat_id = "2147655943"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 1b 8a 96 ?? ?? ?? ?? 30 14 19 83 c6 01 3b f0 7c 02 33 f6}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d5 24 7f 04 30 3c 61 7c 04 3c 7a 7e 12 3c 41 7c 04 3c 5a 7e 0a 8a c8 80 e9 30 80 f9 09 77 0a}  //weight: 1, accuracy: High
        $x_1_3 = "C21234D3-5CC2-4bdd-9BE7-82A34EF3FAE0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Tracur_P_2147655944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.P"
        threat_id = "2147655944"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff b0 9c 00 00 00 [0-160] 8f 45 dc [0-26] 81 75 dc 78 42 76 39}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tracur_AH_2147655945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.AH"
        threat_id = "2147655945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 2e 4a 50 47 74 ?? 3d 2e 6a 70 67 74 ?? 3d 2e 65 78 65 74 ?? 3d 2e 74 6d 70 74 ?? 3d 2e 45 58 45 74 ?? 3d 2e 54 4d 50}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 89 c7 89 d3 90 31 1f 90 83 c7 04 50 58 e2 f5}  //weight: 1, accuracy: Low
        $x_1_3 = {80 30 5a 40 e2 fa 5b 8b 45 08 8b 08 81 f9 14 e2 a4 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Tracur_AF_2147655946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.AF"
        threat_id = "2147655946"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "=.jpgt" ascii //weight: 1
        $x_1_2 = {8b 45 08 8d 40 18 50}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 0c ff 10 83 c4 02 00 54}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tracur_AJ_2147655947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.AJ"
        threat_id = "2147655947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 94 81 00 08 00 00 8b 45 f8 25 ff 00 00 00 8b 4d f4 03 94 81 00 0c 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {c7 45 f8 2b 9f e3 e6 c7 45 fc f7 ad 83 db 68 00 08 00 00 8d 85 00 f8 ff ff}  //weight: 2, accuracy: High
        $x_1_3 = {6c 6f 61 64 65 72 2e 64 6c 6c 00 73 74 61 72 74 00 75 6e 69 6e 73 74 61 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 00 00 22 2c 73 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 4f 75 74 6c 6f 6f 6b 20 45 78 70 72 65 73 73 00 00 00 00 5c 49 6e 62 6f 78 2e 64 62 78 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 4d 53 4c 69 63 65 6e 73 69 6e 67 5c 48 61 72 64 77 61 72 65 49 44 00 00 00 43 6c 69 65 6e 74 48 57 49 44 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tracur_AL_2147655948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.AL"
        threat_id = "2147655948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "1.5 TN swodniW ;0.6 EISM ;elbitapmoc( 0.4/allizoM" wide //weight: 1
        $x_1_2 = {3f 00 3f 00 65 00 3f 00 3f 00 3f 00 3f 00 4d 00 3f 00 3f 00 75 00 3f 00 3f 00 6c 00 3f 00 65 00 3f 00 3f 00 4d 00 3f 00 3f 00 3f 00 6f 00 3f 00 3f 00 3f 00 3f 00 72 00 3f 00 3f 00 70 00 3f 00 3f 00 68 00 3f 00 3f 00 58 00 3f 00 3f 00 3f 00 54 00 3f 00 3f 00 ?? ?? 3f 00 3f 00 63 00 3f 00 3f 00 6f 00 3f 00 3f 00 3f 00 3f 00 6e 00 3f 00 3f 00 69 00 3f 00 3f 00 6d 00 3f 00 65 00 3f 00 3f 00 2e 00 3f 00 65 00 3f 00 3f 00 78 00 3f 00 65 00 3f 00 3f 00 3f 00 3f 00 3f 00}  //weight: 1, accuracy: Low
        $x_1_3 = "AresURL" wide //weight: 1
        $x_1_4 = "ShareAzaURL" wide //weight: 1
        $x_1_5 = "w??w???w??.???v????a????m????p???i???r???e???m???o???l???i???.??c???o??m" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tracur_AM_2147656184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.AM!dll"
        threat_id = "2147656184"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IE MANAGER" wide //weight: 1
        $x_1_2 = "CLSID\\{DE274C2C-2133-4B4B-93B3-8F21486DABC0}\\InProcServer32" wide //weight: 1
        $x_1_3 = {26 75 73 65 72 5f 69 64 3d 00 00 00 3f 74 79 70 65 3d 66 6c 61 73 68 5f 6e 26 64 69 72 5f 6e 61 6d 65 3d}  //weight: 1, accuracy: High
        $x_1_4 = {26 70 61 73 73 77 6f 72 64 3d 00 00 26 61 63 63 6f 75 6e 74 3d 00 00 00 26 6b 65 79 5f 6e 61 6d 65 3d 00 00 26 4f 53 3d}  //weight: 1, accuracy: High
        $x_1_5 = "!Tibia Keylogger\\reckey_RES\\IE\\BHO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Tracur_AN_2147656576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.AN"
        threat_id = "2147656576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\"matches\": [ \"http://*/*\", \"https://*/*\" ]," ascii //weight: 2
        $x_1_2 = "(/\\.bing\\.[a-z]{2,4}" ascii //weight: 1
        $x_1_3 = "\\x6B\\x65\\x79\\x20\\x3A\",\"\\x20\\x73\\x61\\x6C\\x74\\x3A" ascii //weight: 1
        $x_2_4 = {8b 72 28 6a 18 59 31 ff 31 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 49}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tracur_AP_2147656856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.AP"
        threat_id = "2147656856"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 31 c0 0f a2 81 f9 6e 74 65 6c 75 ?? 83 f8 01 75 [0-5] ff e0 [0-1] 61 92 81 ec 04 01 00 00 89 e0 89 e6 68 f8 00 00 00 50 6a 00 ff d2 01 f0 ff 70 fc ff 70 f8 5a 58 3d 2e 65 78 65 74 05 3d 2e 45 58 45}  //weight: 1, accuracy: Low
        $x_1_2 = {89 e0 89 e6 68 ?? 00 00 00 50 6a 00 ff [0-13] 3d 2e 65 78 65 74 05 3d 2e 45 58 45 81 (c4 04 01 00|fa 6c 6c 33)}  //weight: 1, accuracy: Low
        $x_5_3 = {89 44 24 1c 89 c7 50 68 22 07 e4 71 50 e8 ?? ?? ?? ?? 89 85 f4 fd ff ff 58 68 b6 74 75 5d 50 e8 ?? ?? ?? ?? 89 85 ec fd ff ff 68 50 46 b4 59 57 e8}  //weight: 5, accuracy: Low
        $x_5_4 = {e8 17 00 00 00 83 c4 ?? 5f 5e 5d 83 c4 04 5b 5a 83 c4 08 83 c4 04 89 4c 24 04 ff e0}  //weight: 5, accuracy: Low
        $x_5_5 = {81 c1 00 10 00 00 c7 01 90 90 90 90 c7 41 04 90 90 90 90 c7 41 08 90 90 90 90 81 c2 39 8b 00 00 c6 02 e9 51 29 d1 89 4a 01}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tracur_AQ_2147657410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.AQ"
        threat_id = "2147657410"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "(/\\.bing\\.[a-z]{2,4}" ascii //weight: 2
        $x_2_2 = "\"matches\": [ \"http://*/*\", \"https://*/*\" ]," ascii //weight: 2
        $x_2_3 = "TFakeReferrer" ascii //weight: 2
        $x_2_4 = "/login/ /tweet/ action=embed-flash" ascii //weight: 2
        $x_1_5 = "adurl=" ascii //weight: 1
        $x_1_6 = "MasterCard" ascii //weight: 1
        $x_1_7 = "porn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tracur_AS_2147657635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.AS"
        threat_id = "2147657635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dnserrordiagoff_weboc.htm" ascii //weight: 1
        $x_1_2 = "donya-e-eqtesad.com" ascii //weight: 1
        $x_1_3 = "\"enterprise_store_name\": \"Default\", \"enterprise_store_url\": \".\"" ascii //weight: 1
        $x_1_4 = "TFakeReferrer" ascii //weight: 1
        $x_1_5 = "/login/ /tweet/ action=embed-flash" ascii //weight: 1
        $x_1_6 = {5f 42 47 46 49 4c 45 5f [0-15] 5f 43 53 46 49 4c 45 5f}  //weight: 1, accuracy: Low
        $x_1_7 = {0f b6 44 18 ff 8b d6 81 e2 ff 00 00 00 33 c2 83 f8 07 7d 0f 8b 17 b9 01 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tracur_AU_2147658191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.AU"
        threat_id = "2147658191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 69 72 65 66 6f 78 [0-10] 63 68 72 6f 6d 65 [0-10] 69 65 78 70 6c 6f 72 65 [0-53] 73 63 6f 64 65 66}  //weight: 1, accuracy: Low
        $x_1_2 = {43 22 6b 65 79 a3 3a 07 0e 4d 49 47 66 43 41 30}  //weight: 1, accuracy: High
        $x_1_3 = "dnserrordiagoff_weboc.htm" ascii //weight: 1
        $x_1_4 = "!/search/results.php?" ascii //weight: 1
        $x_1_5 = {0a 00 00 00 2f 73 65 61 72 63 68 3f 71 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Tracur_AU_2147658191_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.AU"
        threat_id = "2147658191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 00 62 64 70 63 65 6a 74 7a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 00 62 64 73 6e 65 7a 71 62 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 00 00 62 64 78 76 61 63 64 6a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 00 00 62 72 74 70 75 66 66 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 00 00 62 73 76 72 69 70 77 68 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 00 00 62 73 78 63 61 6b 70 66 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 00 00 63 63 67 74 6f 6c 6d 73 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 00 00 63 6a 6e 77 75 6d 6b 6d 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 00 00 63 6a 70 64 65 71 67 66 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 00 00 63 70 70 74 69 64 73 6d 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 00 00 63 71 68 72 75 64 74 6e 6a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_12 = {00 00 00 63 72 70 77 69 74 67 6e 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_13 = {00 00 00 63 73 64 67 6f 6e 73 67 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_14 = {00 00 00 63 74 7a 6c 69 64 77 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_15 = {00 00 00 63 77 73 66 69 7a 64 73 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_16 = {00 00 00 63 77 78 6e 79 6c 68 7a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_17 = {00 00 00 63 78 6b 77 75 6e 6c 74 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_18 = {00 00 00 64 62 65 78 70 69 64 61 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_19 = {00 00 00 64 64 6c 77 75 62 78 70 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_20 = {00 00 00 64 67 64 73 65 6a 67 64 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_21 = {00 00 00 64 68 67 71 79 68 7a 78 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_22 = {00 00 00 64 6e 7a 70 75 6d 78 7a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_23 = {00 00 00 65 70 30 6c 76 72 31 35 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_24 = {00 00 00 66 64 73 77 61 62 76 70 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_25 = {00 00 00 66 6c 63 6b 6f 6e 66 64 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_26 = {00 00 00 66 6d 74 6b 61 64 62 77 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_27 = {00 00 00 66 73 77 63 75 78 71 7a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_28 = {00 00 00 67 70 62 6d 79 6c 64 6a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_29 = {00 00 00 68 64 70 7a 6f 63 72 73 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_30 = {00 00 00 68 6b 6c 70 65 6e 76 6d 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_31 = {00 00 00 68 6c 68 6c 65 74 72 67 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_32 = {00 00 00 68 71 6c 78 75 76 70 7a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_33 = {00 00 00 68 71 70 67 61 6b 6b 7a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_34 = {00 00 00 68 72 71 77 69 6d 64 63 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_35 = {00 00 00 68 78 76 64 69 77 63 76 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_36 = {00 00 00 6a 66 70 78 6f 63 70 6a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_37 = {00 00 00 6a 68 72 64 6f 63 68 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_38 = {00 00 00 6a 68 77 77 61 6e 67 6e 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_39 = {00 00 00 6a 6c 64 78 75 71 6d 71 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_40 = {00 00 00 6a 6c 6d 67 65 7a 6d 6b 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_41 = {00 00 00 6a 72 71 6c 6f 70 7a 70 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_42 = {00 00 00 6b 64 71 64 75 70 6d 66 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_43 = {00 00 00 6b 66 78 70 61 6a 67 64 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_44 = {00 00 00 6b 6c 77 72 75 71 7a 64 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_45 = {00 00 00 6b 73 64 76 69 71 6b 6d 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_46 = {00 00 00 6b 76 70 73 75 67 64 70 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_47 = {00 00 00 6b 77 72 6b 6f 66 78 68 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_48 = {00 00 00 6c 62 68 71 79 72 6c 7a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_49 = {00 00 00 6c 68 78 68 6f 73 6a 77 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_50 = {00 00 00 6c 6d 66 70 79 63 6c 68 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_51 = {00 00 00 6c 6d 6b 73 75 78 77 76 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_52 = {00 00 00 6c 77 62 71 6f 6d 67 70 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_53 = {00 00 00 6c 7a 74 70 75 7a 64 68 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_54 = {00 00 00 6d 64 73 6c 65 76 6a 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_55 = {00 00 00 6d 6c 63 77 61 72 6c 6d 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_56 = {00 00 00 6d 6c 67 68 75 70 67 62 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_57 = {00 00 00 6d 6c 67 72 6f 71 63 67 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_58 = {00 00 00 6d 71 76 6b 6f 64 78 76 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_59 = {00 00 00 6e 62 70 6c 69 6b 70 76 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_60 = {00 00 00 6e 6a 77 76 65 71 68 68 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_61 = {00 00 00 6e 70 74 77 65 71 62 73 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_62 = {00 00 00 6e 72 70 64 61 6b 7a 63 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_63 = {00 00 00 6e 73 62 6e 69 6b 68 6e 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_64 = {00 00 00 6e 7a 63 68 65 68 6d 7a 6a 6f 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_65 = {00 00 00 70 62 78 77 61 74 6c 7a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_66 = {00 00 00 70 66 6d 62 6f 63 62 6a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_67 = {00 00 00 70 68 71 6e 61 76 77 66 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_68 = {00 00 00 70 6d 6c 72 75 71 71 70 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_69 = {00 00 00 70 6e 6b 70 69 63 6a 68 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_70 = {00 00 00 71 62 71 6d 6f 6a 77 64 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_71 = {00 00 00 71 63 67 64 61 6d 76 6b 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_72 = {00 00 00 71 64 62 62 6f 73 64 64 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_73 = {00 00 00 71 6d 77 77 79 62 63 74 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_74 = {00 00 00 71 6e 76 6c 61 62 63 71 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_75 = {00 00 00 71 73 64 76 6f 76 6e 74 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_76 = {00 00 00 71 76 76 6d 61 6d 76 6b 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_77 = {00 00 00 71 78 6c 74 79 71 68 6b 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_78 = {00 00 00 71 78 72 6a 79 78 64 68 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_79 = {00 00 00 72 62 68 63 61 71 6b 68 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_80 = {00 00 00 72 62 6c 70 79 73 72 76 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_81 = {00 00 00 72 62 73 68 6f 74 6a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_82 = {00 00 00 72 66 73 6c 64 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_83 = {00 00 00 72 66 76 6b 69 78 6d 7a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_84 = {00 00 00 72 6d 78 71 61 6c 7a 76 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_85 = {00 00 00 72 71 67 6d 69 62 7a 6e 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_86 = {00 00 00 72 72 6a 63 61 6a 74 7a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_87 = {00 00 00 72 72 77 6a 79 66 6a 66 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_88 = {00 00 00 72 76 77 70 69 6e 67 67 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_89 = {00 00 00 72 77 6c 74 6f 68 71 62 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_90 = {00 00 00 73 6a 71 67 79 67 68 71 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_91 = {00 00 00 73 6b 7a 62 65 6b 62 6e 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_92 = {00 00 00 73 6c 64 64 69 73 73 65 63 74 65 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_93 = {00 00 00 73 71 62 71 61 7a 63 6d 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_94 = {00 00 00 73 72 73 63 61 6c 65 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_95 = {00 00 00 74 64 72 6c 6f 71 68 73 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_96 = {00 00 00 74 67 62 70 6f 6a 70 64 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_97 = {00 00 00 74 70 76 70 79 7a 68 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_98 = {00 00 00 74 7a 73 68 65 72 78 73 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_99 = {00 00 00 75 72 62 7a 79 6a 6e 66 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_100 = {00 00 00 76 64 67 72 61 62 76 6a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_101 = {00 00 00 76 64 74 73 61 63 7a 77 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_102 = {00 00 00 76 6a 62 70 6f 77 6b 68 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_103 = {00 00 00 76 6e 62 6d 69 74 72 6c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_104 = {00 00 00 76 72 63 74 69 74 67 78 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_105 = {00 00 00 76 73 72 64 79 68 6e 7a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_106 = {00 00 00 76 78 64 72 6f 71 6c 64 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_107 = {00 00 00 77 67 68 64 61 63 70 63 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_108 = {00 00 00 77 6b 6a 78 65 63 76 76 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_109 = {00 00 00 77 71 6d 73 65 62 67 63 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_110 = {00 00 00 77 71 74 7a 6f 6b 72 74 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_111 = {00 00 00 77 77 71 62 69 66 6e 78 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_112 = {00 00 00 78 6e 62 6a 61 73 72 70 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_113 = {00 00 00 78 72 78 6e 75 69 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_114 = {00 00 00 78 78 71 67 79 6e 64 70 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_115 = {00 00 00 78 7a 73 6b 69 67 6d 74 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_116 = {00 00 00 7a 62 6b 6d 79 6d 62 62 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_117 = {00 00 00 7a 66 64 63 79 6e 62 7a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_118 = {00 00 00 7a 6a 78 63 75 64 6a 7a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_119 = {00 00 00 7a 6b 63 77 6f 6b 74 7a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_120 = {00 00 00 7a 6d 6b 62 79 67 6e 7a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_121 = {00 00 00 7a 6d 6b 64 79 73 68 63 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_122 = {00 00 00 7a 70 64 72 79 77 67 64 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_123 = {00 00 00 7a 76 63 76 6f 76 74 62 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_124 = {00 00 00 78 70 6d 70 61 6d 62 6c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_125 = {00 00 00 6d 71 72 68 69 67 67 6d 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Tracur_AV_2147659134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.AV"
        threat_id = "2147659134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "m=%s&z=%s" ascii //weight: 1
        $x_2_2 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 22 2c 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 00 00 00 00 43 68 65 63 6b 65 72}  //weight: 2, accuracy: High
        $x_1_3 = "\\drivers\\null.sys" ascii //weight: 1
        $x_1_4 = {26 66 6d 74 3d 74 65 78 74 00 00 00 26 64 3d}  //weight: 1, accuracy: High
        $x_1_5 = {67 6f 6f 67 6c 65 2e 00 71 3d 00 00 2f 23 00 00 2f 73 65 61 72 63 68 3f}  //weight: 1, accuracy: High
        $x_2_6 = {72 75 6e 64 6c 6c 33 32 2e 65 20 22 25 73 22 2c 25 73 00 [0-4] 43 68 65 63 6b 65 72 00}  //weight: 2, accuracy: Low
        $x_1_7 = {8a 4c 16 01 32 8b ?? ?? ?? ?? 88 0c 10 42 43 3b d7 72 e6}  //weight: 1, accuracy: Low
        $x_2_8 = {8a 08 80 f9 75 75 06 ff 74 24 14 eb 09 80 f9 72 75 0e ff 74 24 30 83 c0 02 e8 ?? ?? ?? ?? eb ?? 80 f9 74 75 ?? 83 c0 02}  //weight: 2, accuracy: Low
        $x_2_9 = {8b 5d f8 80 3c 1f 6b 75 36 80 7c 1f 01 31 75 2f 80 7c 1f 02 20 75 28 80 7c 1f 03 3d 75 21 80 7c 1f 04 22}  //weight: 2, accuracy: High
        $x_2_10 = {8b c8 c1 e8 06 33 c8 42 42 0f b7 02 66 85 c0 75 e4 6b c9 09 8b c1 c1 e8 0b 33 c1 69 c0 01 80 00 00}  //weight: 2, accuracy: High
        $x_1_11 = {68 74 74 70 3a 2f 2f 25 73 2f 63 67 69 2d 62 69 6e 2f 69 6e 64 65 78 3f 25 64 00 00 72 75 6e 64 6c 6c 33 32 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_12 = {00 71 6b 77 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tracur_AY_2147661847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.AY"
        threat_id = "2147661847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 69 72 65 66 6f 78 [0-10] 63 68 72 6f 6d 65 [0-10] 69 65 78 70 6c 6f 72 65 [0-53] 73 63 6f 64 65 66}  //weight: 1, accuracy: Low
        $x_1_2 = "Update Auto Tray Helper" ascii //weight: 1
        $x_1_3 = "dnserrordiagoff_weboc.htm" ascii //weight: 1
        $x_1_4 = "STEP: ERROR WHILE GETTING CLICKS INFO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tracur_AZ_2147662159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.AZ"
        threat_id = "2147662159"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 40 2c 01 74 1b 8b 43 10 83 38 01 75 07 8b c3 e8 ?? ?? ?? ?? 68 10 27 00 00 e8 ?? ?? ?? ?? eb e5}  //weight: 1, accuracy: Low
        $x_1_2 = {68 f4 01 00 00 e8 ?? ?? ?? ?? 6a 00 57 56 e8 ?? ?? ?? ?? 68 f4 01 00 00 e8 ?? ?? ?? ?? 43 83 fb 03 77}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tracur_BB_2147664559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.BB"
        threat_id = "2147664559"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 f2 04 04 00 00 8b 45 fc 8b 40 10 80 7c f0 10 00 75 05 89 55 f0 eb 28}  //weight: 1, accuracy: High
        $x_1_2 = {69 c3 04 04 00 00 8b 7d fc 8b 7f 10 dd 44 c7 20 8b 45 fc 8b 40 10 dc 5c f0 20 df e0}  //weight: 1, accuracy: High
        $x_1_3 = {89 55 fc 89 45 f8 60 ff 75 fc 8b 45 f8 83 c0 18 50 89 c1 e8 08 00 00 00 83 c4 08 e9 a9 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Tracur_BD_2147669012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.BD"
        threat_id = "2147669012"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c6 47 0e 01 89 77 10 c7 47 14 ff ff ff ff 8b 47 10 48 74 05 48 74 0b eb 10 c7 47 14 b0 04 00 00 eb 07 c7 47 14 3c 00 00 00 8b c7 e8}  //weight: 2, accuracy: High
        $x_2_2 = {bb 01 00 00 00 3b fb 7c 53 8b c3 b9 05 00 00 00 99 f7 f9 85 d2 75 21 b8 0c 00 00 00 e8}  //weight: 2, accuracy: High
        $x_2_3 = {80 bd c0 df ff ff 00 74 0c 83 bd bc df ff ff 01 75 03 ff 45 f8 43 81 fb ff 00 00 00 75 d2 69 45 f8 20 20 00 00 83 c0 04 e8}  //weight: 2, accuracy: High
        $x_1_4 = "Lake\\LakeControl\\3.0\\Filters" ascii //weight: 1
        $x_1_5 = {0d 00 ff ff ff 40 8a 84 85 e8 fb ff ff 8b 55 ec 30 04 3a 47 ff 4d e8 75 88 8b 45 fc}  //weight: 1, accuracy: High
        $x_2_6 = {6f 3a 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 62 3a 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 61 3a 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 63 3a 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 76 3a 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tracur_BE_2147670320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.BE"
        threat_id = "2147670320"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 45 f8 83 ee 01 72 0e 74 20 4e 0f 84 a2 00 00 00 e9 ac 00 00 00 a1 ?? ?? ?? 00 89 45 f4 c7 45 f8 e9 05 00 00 e9 98 00 00 00 a1}  //weight: 10, accuracy: Low
        $x_10_2 = {80 38 78 75 3f 80 78 01 31 75 39 80 78 02 3d 75 33 8b 45 ec e8 ?? ?? fe ff 8b d0 4a 83 ea 02 7c 3e}  //weight: 10, accuracy: Low
        $x_10_3 = {8d 55 ef 8a 18 30 1a 4a 48 41 75 f7 8d 55 d8 8d 45 e8 b9 08 00 00 00 e8}  //weight: 10, accuracy: High
        $x_2_4 = "\\x31\\x38\\x34\\x2E\\x31\\x37\\x33\\x2E\\x31\\x38\\x31\\x2E\\x35\\x35\\x2F" ascii //weight: 2
        $x_2_5 = {ce 3f 82 f6 6a 03 49 54 8f 93 fb 87 71 1d 7a fd}  //weight: 2, accuracy: High
        $x_2_6 = {ec c3 92 33 31 2e 93 06 e4 a6 53 03 ae 29 35 2e}  //weight: 2, accuracy: High
        $x_2_7 = {ff 5a 36 f2 c6 b2 03 d6 c8 44 0b 16 b0 3a e8 21 66 83 c8 b6 7b 92 71 5a}  //weight: 2, accuracy: High
        $x_1_8 = {31 42 ca 9e 4c f6 cb 82 99 24 ed c4 05 0f 99 cf 07}  //weight: 1, accuracy: High
        $x_1_9 = {ae 9d 28 87 f6 f4 5a e8 ae 1d 99 80 b5 d6 2a e9}  //weight: 1, accuracy: High
        $x_1_10 = {3d 9c 5a c0 52 6d 4b da 0a 8e df 8c 45 1f c4 78}  //weight: 1, accuracy: High
        $x_1_11 = {cb e4 49 97 25 49 85 78 4d 26 80 6b 60 e2 bc 01}  //weight: 1, accuracy: High
        $x_1_12 = {8e 2a e2 71 6e 1e 11 b3 cf 0e 64 6d 6d ab e1 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_2_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tracur_BF_2147678520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.BF"
        threat_id = "2147678520"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 4a 2c 3d fe fe fe fe 75 1c b8 ?? ?? ?? ?? 89 45 fc 8b d3 8d 45 fc b9 04 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {83 fa 50 72 46 60 8b 7d fc 31 c0 0f a2 ab 93 ab 91 ab 92 ab 31 c0 40 0f a2}  //weight: 1, accuracy: High
        $x_1_3 = {8b 53 18 81 7c 82 24 00 14 00 00 0f 82 ?? ?? ?? ?? 8d 4d f8 8b d6 8b c3 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Tracur_BI_2147680334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.BI"
        threat_id = "2147680334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {71 6b 77 3d 00}  //weight: 1, accuracy: High
        $x_1_2 = "m=%s&z=%s" ascii //weight: 1
        $x_1_3 = {8a 4c 16 01 32 8b ?? ?? ?? ?? 88 0c 10 42 43 3b d7 72 e6}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 5d f8 80 3c 1f 6b 75 36 80 7c 1f 01 31 75 2f 80 7c 1f 02 20 75 28 80 7c 1f 03 3d 75 21 80 7c 1f 04 22}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Tracur_A_2147680336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.gen!A"
        threat_id = "2147680336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fa 22 67 3f 7a 74 ?? 81 fa 67 22 7a 3f 0f 84 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {81 fa 30 75 2d 68 0f 84 ?? ?? 00 00 81 fa 3e 7b 23 66 0f 84 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 75 08 83 c6 04 83 e9 04 89 f7 ac 34 90 01 01 89 c3 83 e3 07 83 fb 00 75 01 46 aa e2 ef}  //weight: 1, accuracy: High
        $x_1_4 = {bb 01 00 00 00 3b fb 7c 53 8b c3 b9 05 00 00 00 99 f7 f9 85 d2 75 21 b8 0c 00 00 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Tracur_B_2147682021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tracur.gen!B"
        threat_id = "2147682021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 18 8b f0 5f 5b 85 f6 74 21 8b 06 8b 48 28 85 c9 74 18 8b 46 04 03 c1 74 11 6a ff 6a 01 6a 00 ff d0 85 c0 75 05 e8 ?? ?? ?? ?? 5e 33 c0 40 c9 c2 08 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

