rule Worm_Win32_Rebhip_A_2147629622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rebhip.A"
        threat_id = "2147629622"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rebhip"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_x_X_UPDATE_X_x_" ascii //weight: 10
        $x_10_2 = "_x_X_PASSWORDLIST_X_x_" ascii //weight: 10
        $x_10_3 = "_x_X_BLOCKMOUSE_X_x_" ascii //weight: 10
        $x_10_4 = "XX--XX--XX.txt" ascii //weight: 10
        $x_1_5 = "MSN.abc" ascii //weight: 1
        $x_1_6 = "FIREFOX.abc" ascii //weight: 1
        $x_1_7 = "IELOGIN.abc" ascii //weight: 1
        $x_1_8 = "IEPASS.abc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Rebhip_A_2147629622_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rebhip.A"
        threat_id = "2147629622"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rebhip"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 54 1a ff 80 f2 ?? 88 54 18 ff 43 4e 75 e6}  //weight: 1, accuracy: Low
        $x_1_2 = {81 ea 00 01 00 00 75 27 8d 85 fa fe ff ff 50 e8 ?? ?? ?? ?? 6a 00 8d 45 fa 50 8d 85 fa fe ff ff 50 8b 43 04 50 8b 03 50 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {be 65 00 00 00 8b 1d ?? ?? ?? ?? 83 3b 00 74 32 8b 03 ba 6c ba 40 00 e8 ?? ?? ?? ?? 74 24}  //weight: 1, accuracy: Low
        $x_1_4 = {80 e3 02 80 e3 01 80 e3 04 33 c0 8a c3 50 56 e8 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 83 f8 01 1b c0 40 88 45 fb}  //weight: 1, accuracy: Low
        $x_1_5 = {eb 3d ff 36 8d 45 fc 8b d3 e8 ?? ?? ?? ?? ff 75 fc 68 ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? 33 d2 52 50 8d 45 f8 e8 ?? ?? ?? ?? ff 75 f8 68 ?? ?? ?? ?? 8b c6 ba 05 00 00 00 e8 ?? ?? ?? ?? 83 c3 04 80 3b 00 75 be}  //weight: 1, accuracy: Low
        $x_1_6 = {66 83 f8 01 75 74 6a 10 e8 ?? ?? ?? ?? 66 85 c0 7d 34 8b 07 e8 ?? ?? ?? ?? 85 c0 0f 8e ?? ?? ?? ?? 8b 07 e8 ?? ?? ?? ?? 8b 17 80 7c 02 ff 7e}  //weight: 1, accuracy: Low
        $x_1_7 = {75 48 6a 40 68 00 30 00 00 68 f4 01 00 00 6a 00 53 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_Rebhip_F_2147636352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rebhip.F"
        threat_id = "2147636352"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rebhip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\LimeWire\\\\" wide //weight: 1
        $x_2_2 = "ZipSpread" ascii //weight: 2
        $x_3_3 = "AntiMalwarebytes" ascii //weight: 3
        $x_3_4 = "shellexecute=USB Disk Security v.1.8.0.1.exe" wide //weight: 3
        $x_3_5 = "sc.exe config AntiVirService start= disabled" wide //weight: 3
        $x_2_6 = "AVKillersinBinder" ascii //weight: 2
        $x_2_7 = "AeonHackRunPE" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Rebhip_I_2147640259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rebhip.I"
        threat_id = "2147640259"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rebhip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "borlo 1.9.7 src\\WindowsApplication1\\obj\\Debug\\Winlogon.pdb" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Rebhip_V_2147694230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rebhip.V"
        threat_id = "2147694230"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rebhip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CG-CG-CG-CG" wide //weight: 1
        $x_1_2 = "XX-XX-XX-XX" wide //weight: 1
        $x_1_3 = {08 00 43 00 45 00 52 00 42 00 45 00 52 00 55 00 53 00}  //weight: 1, accuracy: High
        $x_1_4 = {06 00 53 00 50 00 59 00 4e 00 45 00 54 00}  //weight: 1, accuracy: High
        $x_5_5 = {8a 54 1a ff 80 f2 bc 88 54 18 ff 43 4e 75 e6}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Rebhip_W_2147694566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rebhip.W"
        threat_id = "2147694566"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rebhip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 70 79 4e 65 74 43 6f 6e 66 69 67 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {43 65 72 62 65 72 75 73 20 43 6f 6e 66 69 67 46 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {43 65 72 62 65 72 75 73 20 5b 52 41 54 5d 20 00}  //weight: 1, accuracy: High
        $x_1_4 = {55 6e 69 74 50 61 73 73 77 6f 72 64 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {78 78 78 79 79 79 7a 7a 7a 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {72 65 63 65 62 65 72 63 6f 6e 66 69 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Worm_Win32_Rebhip_W_2147694597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rebhip.W!dll"
        threat_id = "2147694597"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rebhip"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 74 61 72 74 50 65 72 73 69 73 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 4f 46 54 57 41 52 45 5c 43 65 72 62 65 72 75 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {5f 50 65 72 73 69 73 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {5f 53 61 69 72 00}  //weight: 1, accuracy: High
        $x_1_5 = {50 6c 65 61 73 65 53 74 6f 70 2e 73 70 79 00}  //weight: 1, accuracy: High
        $x_1_6 = {55 6e 69 74 50 65 72 73 69 73 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Worm_Win32_Rebhip_X_2147694819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rebhip.X"
        threat_id = "2147694819"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rebhip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "x_X_BLOCKMOUSE" ascii //weight: 1
        $x_1_2 = "_x_X_PASSWORD" ascii //weight: 1
        $x_1_3 = "####@#### ###" ascii //weight: 1
        $x_1_4 = "UnitComandos" ascii //weight: 1
        $x_1_5 = "CG-CG-CG-CG" ascii //weight: 1
        $x_1_6 = "XX-XX-XX-XX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Worm_Win32_Rebhip_Y_2147695419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rebhip.Y"
        threat_id = "2147695419"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rebhip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "9182736450zaybxcwdveuftgshriqjpkolmnZA" wide //weight: 1
        $x_1_2 = "frmLogin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Rebhip_H_2147697157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rebhip.H!pkg"
        threat_id = "2147697157"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rebhip"
        severity = "Critical"
        info = "pkg: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_getdesktoppreviewinfo" wide //weight: 1
        $x_1_2 = "_webcamlist" wide //weight: 1
        $x_1_3 = "_updateserverlocal" wide //weight: 1
        $x_1_4 = "Spy-Net " wide //weight: 1
        $x_1_5 = "_uploadandexecute" wide //weight: 1
        $x_1_6 = "_getpasswords" wide //weight: 1
        $x_1_7 = "_proxystop|_noreply" wide //weight: 1
        $x_1_8 = "_fdiversos" wide //weight: 1
        $x_1_9 = "_keylogger" wide //weight: 1
        $x_1_10 = "_fmcheckrar|" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

