rule PWS_Win32_Stimilina_A_2147694882_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Stimilina.A"
        threat_id = "2147694882"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Stimilina"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "config/SteamAppData.vdf" ascii //weight: 1
        $x_1_2 = "/market/eligibilitycheck/?goto=" ascii //weight: 1
        $x_1_3 = "/ParseInv?id=" ascii //weight: 1
        $x_1_4 = "Alex\\documents\\" ascii //weight: 1
        $x_1_5 = "/half_life_3/index.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_Stimilina_B_2147695034_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Stimilina.B"
        threat_id = "2147695034"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Stimilina"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Valve\\Steam" ascii //weight: 1
        $x_1_2 = "/SteamAppData.vdf" ascii //weight: 1
        $x_1_3 = "\\loginusers.vdf" ascii //weight: 1
        $x_1_4 = "Steam - Error" ascii //weight: 1
        $x_2_5 = "Login to steam faled." ascii //weight: 2
        $x_8_6 = "ssfn*.*" ascii //weight: 8
        $x_8_7 = "\\Steam2.exe" ascii //weight: 8
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Stimilina_C_2147708984_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Stimilina.C!bit"
        threat_id = "2147708984"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Stimilina"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "login=%s&passw=%s" ascii //weight: 1
        $x_1_2 = "Steam.exe" wide //weight: 1
        $x_1_3 = {b8 44 65 00 00 66 89 46 ?? b8 74 6f 00 00 66 89 46 ?? b8 75 72 00 00 66 89 46 ?? b8 73 21 00 00 66 89 46}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Stimilina_D_2147722554_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Stimilina.D!bit"
        threat_id = "2147722554"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Stimilina"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\" wide //weight: 1
        $x_1_2 = "%LOCALAPPDATA%\\Amigo\\User Data\\" wide //weight: 1
        $x_1_3 = "%APPDATA%\\filezilla\\recentservers.xml" wide //weight: 1
        $x_1_4 = "\\Config\\*.vdf" wide //weight: 1
        $x_1_5 = "\\wallet.dat" wide //weight: 1
        $x_1_6 = "Software\\Valve\\Steam" wide //weight: 1
        $x_1_7 = "195.3.207.69/gate.php" ascii //weight: 1
        $x_1_8 = "dsfsd4fs4df65sd656" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule PWS_Win32_Stimilina_E_2147728120_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Stimilina.E!bit"
        threat_id = "2147728120"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Stimilina"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 4c 11 ff 81 f1 ?? ?? ?? ?? 03 d9 8b cb c1 e1 ?? 8b f3 c1 ee ?? 0b ce 2b d9 42 48}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 12 8a 54 32 ff 8b 4d ?? 8a 4c 19 ff 32 d1 88 54 30 ff}  //weight: 1, accuracy: Low
        $x_1_3 = "Software\\Valve\\Steam" wide //weight: 1
        $x_1_4 = "\\Config\\*.vdf" wide //weight: 1
        $x_1_5 = "\\wallet.dat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Stimilina_F_2147730747_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Stimilina.F!bit"
        threat_id = "2147730747"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Stimilina"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41 41 eb 03 83 c1 05 01 c1}  //weight: 1, accuracy: High
        $x_1_2 = {83 f8 07 75 1c 6a 01 e8 ?? ?? ff ff 25 00 ff 00 00 3d 00 0d 00 00 74 07 3d 00 04 00 00 75 02 b3 01 8b c3 5b c3}  //weight: 1, accuracy: Low
        $x_1_3 = "/c %WINDIR%\\system32\\timeout.exe 3 & del" wide //weight: 1
        $x_1_4 = "mbhd.wallet.aes" wide //weight: 1
        $x_1_5 = "mbhd.checkpoints" wide //weight: 1
        $x_1_6 = "mbhd.spvchain" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

