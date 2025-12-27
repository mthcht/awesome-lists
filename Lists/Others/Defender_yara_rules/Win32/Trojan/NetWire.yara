rule Trojan_Win32_NetWire_YL_2147741010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetWire.YL"
        threat_id = "2147741010"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWire"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "call :deleteSelf&exit /b" ascii //weight: 1
        $x_1_2 = "DEL /s \"%s\" >nul 2>&1" ascii //weight: 1
        $x_1_3 = "ping 192.0.2.2 -n 1 -w %d >nul 2>&1" ascii //weight: 1
        $x_1_4 = ":deleteSelf" ascii //weight: 1
        $x_1_5 = "start /b \"\" cmd /c del \"%%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetWire_RA_2147742273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetWire.RA!MTB"
        threat_id = "2147742273"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 88 28 32 9f 00 40 3b f8 77 f5}  //weight: 1, accuracy: High
        $x_1_2 = {33 0c 83 8b 55 08 8b 45 f8 89 0c 82}  //weight: 1, accuracy: High
        $x_1_3 = "CallNextHookEx" ascii //weight: 1
        $x_1_4 = "ipconfig.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetWire_RA_2147742273_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetWire.RA!MTB"
        threat_id = "2147742273"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AppData\\Roaming\\Logs\\" ascii //weight: 2
        $x_1_2 = "HostId-" ascii //weight: 1
        $x_3_3 = "HKCU\\SOFTWARE\\NetWire" ascii //weight: 3
        $x_1_4 = "Install Date" ascii //weight: 1
        $x_1_5 = "DARKEYED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NetWire_RA_2147742273_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetWire.RA!MTB"
        threat_id = "2147742273"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SendBugConnect_Click" ascii //weight: 1
        $x_1_2 = "Bugreporttxt" ascii //weight: 1
        $x_1_3 = "ShellExecuteA" ascii //weight: 1
        $x_1_4 = "C:\\Windows\\SysWow64\\DXAnimatedGIF.oca" ascii //weight: 1
        $x_1_5 = "mailto\\shell\\open\\command" ascii //weight: 1
        $x_1_6 = "hmmapi.pdb" ascii //weight: 1
        $x_1_7 = "FileEnDecryptor (uses RC4 for endecryption)" ascii //weight: 1
        $x_1_8 = "\\Rc4config.ini" ascii //weight: 1
        $x_1_9 = "GetCurrentProcess" ascii //weight: 1
        $x_1_10 = "RegEnumKeyExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetWire_DSK_2147742754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetWire.DSK!MTB"
        threat_id = "2147742754"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 c2 59 11 00 00 a1 ?? ?? ?? ?? 8b ca a3 ?? ?? ?? ?? 31 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetWire_DW_2147743305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetWire.DW!MTB"
        threat_id = "2147743305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Log Started]" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\NetWire" ascii //weight: 1
        $x_1_3 = "Install Date" ascii //weight: 1
        $x_1_4 = "%s\\%s.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetWire_RA_2147743643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetWire.RA!!NetWire.A"
        threat_id = "2147743643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWire"
        severity = "Critical"
        info = "NetWire: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AppData\\Roaming\\Logs\\" ascii //weight: 1
        $x_1_2 = "HostId" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\NetWire" ascii //weight: 1
        $x_1_4 = "Install Date" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetWire_RB_2147743644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetWire.RB!!NetWire.A"
        threat_id = "2147743644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWire"
        severity = "Critical"
        info = "NetWire: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Log Started]" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\NetWire" ascii //weight: 1
        $x_1_3 = "Install Date" ascii //weight: 1
        $x_1_4 = "%s\\%s.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetWire_AB_2147743952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetWire.AB!!NetWire.gen!B"
        threat_id = "2147743952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWire"
        severity = "Critical"
        info = "NetWire: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LOGONSERVER=\\" ascii //weight: 1
        $x_1_2 = "AppData\\Roaming\\Logs\\" ascii //weight: 1
        $x_1_3 = "COMPUTERNAME=" ascii //weight: 1
        $x_1_4 = "amariceo.duckdns.org" ascii //weight: 1
        $x_1_5 = "FP_NO_HOST_CHECK=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetWire_D_2147744064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetWire.D!MTB"
        threat_id = "2147744064"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LOGONSERVER=\\" ascii //weight: 1
        $x_1_2 = "AppData\\Roaming\\Logs\\" ascii //weight: 1
        $x_1_3 = "COMPUTERNAME=" ascii //weight: 1
        $x_1_4 = "amariceo.duckdns.org" ascii //weight: 1
        $x_1_5 = "FP_NO_HOST_CHECK=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_NetWire_BD_2147745673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetWire.BD!!NetWire.gen!BD"
        threat_id = "2147745673"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWire"
        severity = "Critical"
        info = "NetWire: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "BD: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ping 192.0.2.2 -n 1 -w %d >nul 2>&1" ascii //weight: 1
        $x_1_2 = "call :deleteSelf&exit /b" ascii //weight: 1
        $x_1_3 = ":deleteSelf" ascii //weight: 1
        $x_1_4 = "start /b \"\" cmd /c del \"%%" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\NetWire" ascii //weight: 1
        $x_1_6 = "[Log Started] - [" ascii //weight: 1
        $x_1_7 = "[D00Wg md85]" ascii //weight: 1
        $x_1_8 = "[D00Wg us]" ascii //weight: 1
        $x_1_9 = "[MY0Wii mWYw]" ascii //weight: 1
        $x_1_10 = "SeaMonkey" ascii //weight: 1
        $x_1_11 = "encryptedUsername" ascii //weight: 1
        $x_1_12 = "encryptedPassword" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_Win32_NetWire_BD_2147746107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetWire.BD!MTB"
        threat_id = "2147746107"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ping 192.0.2.2 -n 1 -w %d >nul 2>&1" ascii //weight: 1
        $x_1_2 = "call :deleteSelf&exit /b" ascii //weight: 1
        $x_1_3 = ":deleteSelf" ascii //weight: 1
        $x_1_4 = "start /b \"\" cmd /c del \"%%" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\NetWire" ascii //weight: 1
        $x_1_6 = "[Log Started] - [" ascii //weight: 1
        $x_1_7 = "[D00Wg md85]" ascii //weight: 1
        $x_1_8 = "[D00Wg us]" ascii //weight: 1
        $x_1_9 = "[MY0Wii mWYw]" ascii //weight: 1
        $x_1_10 = "SeaMonkey" ascii //weight: 1
        $x_1_11 = "encryptedUsername" ascii //weight: 1
        $x_1_12 = "encryptedPassword" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_Win32_NetWire_A_2147753707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetWire.A!MSR"
        threat_id = "2147753707"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWire"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 85 c0 66 3d 1b 60 83 f6 00 85 c0 85 c0 85 c0 85 c0 83 f6 00 66 3d 33 51 85 c0 be [0-8] 83 f6 00 85 c0 66 3d 10 fb 66 3d bb 3f 66 3d a7 27 85 c0 83 f6 00 83 f6 00 66 3d 1c b3 83 f6 00 66 3d 94 70 66 3d 2d 09 81 c6 [0-8] 83 f6 00 83 f6 00 66 3d 8e 6c 85 c0 85 c0 83 f6 00 85 c0 83 f6 00 39 30 66 0f 6e fe 75 94}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetWire_AP_2147834216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetWire.AP!MTB"
        threat_id = "2147834216"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8d 43 01 0f b6 d8 8a 54 1c 14 0f b6 c2 03 c5 0f b6 e8 8b 44 24 10 8a 4c 2c 14 88 4c 1c 14 02 ca 0f b6 c9 88 54 2c 14 0f b6 4c 0c 14 30 0c 07 47 3b fe 7c}  //weight: 3, accuracy: High
        $x_1_2 = "MT_qUDrj\\F4Y0W6W85\\U4RSWg6\\PQ00dR5zd064WR" ascii //weight: 1
        $x_1_3 = "sQ0sid\\CYYWQR56.fli" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetWire_MA_2147838775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetWire.MA!MTB"
        threat_id = "2147838775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 74 14 8b 0c 17 88 ae 86 e8 9f 82 1b 76 04 82 1d 75 12 af 06 6e 21 ce 9c 7c}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetWire_GHK_2147844266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetWire.GHK!MTB"
        threat_id = "2147844266"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 04 31 30 86 ?? ?? ?? ?? 8b 45 f4 8d 88 ?? ?? ?? ?? b8 ?? ?? ?? ?? 03 ce f7 e1 2b ca d1 e9 03 ca c1 e9 05 6b c1 26 b9 ?? ?? ?? ?? 2b c8 0f b6 04 31 30 86 ?? ?? ?? ?? 83 c6 ?? 81 fe ?? ?? ?? ?? 0f 82}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetWire_NA_2147915615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetWire.NA!MTB"
        threat_id = "2147915615"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "= EXECUTE ( \"Execute\" )" ascii //weight: 2
        $x_2_2 = "( $VDATA , $VCRYPTKEY , $DDDS =" ascii //weight: 2
        $x_2_3 = "( $RESNAME , $FILENAME , $RUN , $RUNONCE , $DIR )" ascii //weight: 2
        $x_2_4 = "( \"amsi1\" , \"5\" ) , EXECUTE ( \"1\" ) )" ascii //weight: 2
        $x_2_5 = "( \"UevAgentPolicyGenerator2\" , \"5\" ) , EXECUTE ( \"1\" ) )" ascii //weight: 2
        $x_2_6 = "= @APPDATADIR & \"\\" ascii //weight: 2
        $x_2_7 = "= @SCRIPTFULLPATH" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetWire_GMT_2147957175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetWire.GMT!MTB"
        threat_id = "2147957175"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "ACTXPRXY3" wide //weight: 5
        $x_5_2 = {41 00 54 00 ?? 00 52 00 32 00 0c 00 52 00 48 00 49 00 54 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

