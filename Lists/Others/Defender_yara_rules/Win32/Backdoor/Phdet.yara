rule Backdoor_Win32_Phdet_D_2147600920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Phdet.D"
        threat_id = "2147600920"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Phdet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{F3532CE1-1832-11B1-920A-25000A276A57}" ascii //weight: 1
        $x_1_2 = "This service downloading and installing Windows security updates" ascii //weight: 1
        $x_1_3 = "flood" ascii //weight: 1
        $x_1_4 = "http://somehost.net/stat.php" ascii //weight: 1
        $x_1_5 = "_bot.exe" ascii //weight: 1
        $x_1_6 = "BlackEnergy DDoS Bot;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Phdet_A_2147600922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Phdet.gen!A"
        threat_id = "2147600922"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Phdet"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {e9 75 01 00 00 6a 03 68 ?? ?? ?? ?? 56 e8 ?? ?? 00 00 83 c4 0c 85 c0 75 18 e8 ?? ?? ff ff 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 6a 00}  //weight: 5, accuracy: Low
        $x_5_2 = {c7 85 d0 fb ff ff 01 00 01 00 8d 85 d0 fb ff ff 50 8b 8d ec fe ff ff 51 ff 15 ?? ?? ?? ?? 8b 55 08 89 95 88 fc ff ff}  //weight: 5, accuracy: Low
        $x_5_3 = {74 6e 53 8b 1d ?? ?? ?? ?? 55 6a fe ff d3 8b 2d ?? ?? ?? ?? 50 ff d5 6a 00 68 ?? ?? ?? ?? e8 ?? ?? ff ff 68 ?? ?? ?? ?? 56 e8}  //weight: 5, accuracy: Low
        $x_1_4 = {8d 54 24 04 cd 2e c2 14 00 b8 01 00 00 00 c2 14 00 0e 00 83 3d ?? ?? ?? ?? 00 74 0e a1}  //weight: 1, accuracy: Low
        $x_1_5 = {8b cc 0f 34 c3}  //weight: 1, accuracy: High
        $x_1_6 = {fa 9c 60 ff 15 ?? ?? ?? ?? 61 9d ba ?? ?? ?? ?? 0f 35}  //weight: 1, accuracy: Low
        $x_1_7 = {25 64 2e 25 64 2e 25 64 2e 25 64 00 25 64 2e}  //weight: 1, accuracy: High
        $x_1_8 = {64 69 65 00}  //weight: 1, accuracy: High
        $x_1_9 = {66 6c 6f 6f 64 00}  //weight: 1, accuracy: High
        $x_1_10 = "&build_id=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Phdet_G_2147611908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Phdet.G"
        threat_id = "2147611908"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Phdet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "This service downloading and installing Windows security updates" ascii //weight: 1
        $x_1_2 = "GET http://yahoo.com" ascii //weight: 1
        $x_1_3 = "application/x-www-form-urlencoded" ascii //weight: 1
        $x_1_4 = "v=%s&id=%s&socks=%d&http=%d&ping=%d&speed=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Phdet_B_2147644187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Phdet.gen!B"
        threat_id = "2147644187"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Phdet"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 30 ef 02 98 33 f6 33 db 56 43 53 e8 ?? ?? ?? ?? 68 04 01 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 2f e0 1d aa 56 53 c7 85 ?? ?? ?? ?? 01 00 01 00}  //weight: 1, accuracy: Low
        $x_1_3 = {74 14 53 57 6a 02 e8 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 26 80 ac c8}  //weight: 1, accuracy: Low
        $x_1_4 = {47 65 74 42 6f 74 49 64 65 6e 74 00 50 6c 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Phdet_R_2147670385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Phdet.R"
        threat_id = "2147670385"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Phdet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 42 06 39 45 f4 73 36 68 ?? ?? ?? ?? 8b 4d f8 51 e8 ?? ?? 00 00 83 c4}  //weight: 1, accuracy: Low
        $x_1_2 = {68 9c 45 6e a0 6a ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Phdet_S_2147681684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Phdet.S"
        threat_id = "2147681684"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Phdet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 44 4e 57 50 ff 15 09 00 81 7d ?? 00 30 00 00 72}  //weight: 1, accuracy: Low
        $x_1_2 = {56 8b 74 24 08 6a 02 56 ff 15 ?? ?? ?? ?? 85 c0 75 ?? b8 4d 5a 00 00 66 39 06 75}  //weight: 1, accuracy: Low
        $x_1_3 = {22 25 73 22 20 2f 65 78 70 6c 6f 69 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {5f 50 59 41 4c 4f 41 44 00}  //weight: 1, accuracy: High
        $x_1_5 = {7b 33 44 35 41 31 36 39 34 2d 43 43 32 43 2d 34 65 65 37 2d 41 33 44 35 2d 41 38 37 39 41 39 45 33 41 36 32 41 7d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Phdet_T_2147684784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Phdet.T"
        threat_id = "2147684784"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Phdet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d b7 00 00 00 0f 84 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 85 ?? ?? ff ff 81 bd ?? ?? ff ff 28 0a 00 00 74 ?? 81 bd ?? ?? ff ff ce 0e 00 00 74}  //weight: 1, accuracy: Low
        $x_1_2 = {68 6f 45 59 4e 6a 01 e8}  //weight: 1, accuracy: High
        $x_1_3 = "-n 3  & move \"%s\" \"%s\" &" ascii //weight: 1
        $x_1_4 = {83 78 04 04 74 ?? 81 bd ?? ?? ff ff 70 17 00 00 0f 82 ?? ?? ?? ?? 8b 85 ?? ?? ff ff 83 78 04 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Phdet_U_2147689625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Phdet.U"
        threat_id = "2147689625"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Phdet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 61 6b 65 43 61 63 68 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {4d 43 53 46 5f 43 6f 6e 66 69 67 00}  //weight: 1, accuracy: High
        $x_1_3 = {75 70 64 63 66 67 00 00 6c 64 70 6c 67 00}  //weight: 1, accuracy: High
        $x_1_4 = {30 78 25 30 32 68 78 25 30 32 68 78 25 30 32 68 78 25 30 32 68 78 25 30 32 68 78 25 30 32 68 78 00}  //weight: 1, accuracy: High
        $x_1_5 = "id=%s&bid=" ascii //weight: 1
        $x_1_6 = {c7 45 d4 7b 43 44 35 c7 45 d8 36 31 37 33 c7 45 dc 44 2d 31 41 c7 45 e0 37 44 2d 34 c7 45 e4 45 39 39 2d c7 45 e8 38 31 30 39 c7 45 ec 2d 41 37 31 c7 45 f0 42 42 30 34 c7 45 f4 32 36 33 44}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_Phdet_V_2147689626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Phdet.V"
        threat_id = "2147689626"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Phdet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 e4 6b 00 65 00 c7 45 e8 72 00 6e 00 c7 45 ec 65 00 6c 00 c7 45 f0 33 00 32 00 c7 45 f4 2e 00 64 00 c7 45 f8 6c 00 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {61 64 76 61 c7 45 ?? 70 69 33 32 c7 45 ?? 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {83 ec 10 c7 45 ec 5a 00 00 00 c7 45 e0 46 00 00 00 c7 45 e8 5a 00 00 00 c7 45 e4 46 00 00 00 6a 01 8d ?? e0 ?? e8 ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Phdet_W_2147689627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Phdet.W"
        threat_id = "2147689627"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Phdet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 d0 68 61 6e 63}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 d4 65 64 20 43 e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_10_3 = {c7 45 e0 70 68 69 63 c7 45 e4 20 50 72 6f c7 45 e8 76 69 64 65 c7 45 ec 72 20 76 31 e9}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Phdet_X_2147695463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Phdet.X!dha"
        threat_id = "2147695463"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Phdet"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 61 6b 65 43 61 63 68 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {75 70 64 63 66 67 00}  //weight: 1, accuracy: High
        $x_1_3 = {6c 64 70 6c 67 00}  //weight: 1, accuracy: High
        $x_1_4 = {75 6e 6c 70 6c 67 00}  //weight: 1, accuracy: High
        $x_1_5 = {30 78 25 30 32 68 78 25 30 32 68 78 25 30 32 68 78 25 30 32 68 78 25 30 32 68 78 25 30 32 68 78 00}  //weight: 1, accuracy: High
        $x_10_6 = "**del.DisableFirstRunCustomize" ascii //weight: 10
        $x_10_7 = "/s /c \"for /L %%i in (1,1,100) do (del /F \"%s\" & ping localhost -n 2 & if not exist \"%s\" Exit 1)\"" ascii //weight: 10
        $x_10_8 = "NoProtectedModeBDisableFirstRunC" ascii //weight: 10
        $x_10_9 = "\\Microsoft\\WindSoftware\\Policieet Settings" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

