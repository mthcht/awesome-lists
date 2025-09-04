rule Trojan_Win32_Remcos_SD_2147734492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.SD!MTB"
        threat_id = "2147734492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Offline Keylogger" ascii //weight: 1
        $x_1_2 = "Screenshots" ascii //weight: 1
        $x_1_3 = "MicRecords" ascii //weight: 1
        $x_1_4 = "remcos" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Remcos_SA_2147734757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.SA!MTB"
        threat_id = "2147734757"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cb 8b c1 83 e0 ?? 8a 44 05 ?? 30 81 ?? ?? ?? ?? 41 81 f9 ?? ?? 00 00 72 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? b8 02 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_DL_2147740456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.DL!MTB"
        threat_id = "2147740456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce 2b d6 bf ?? ?? ?? ?? 8d 9b 00 00 00 00 8a 04 0a 34 ?? 88 01 41 4f 75 ?? 8d 4c 24 10 51 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_DM_2147740482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.DM!MTB"
        threat_id = "2147740482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 0a 80 f3 ?? 88 19 83 c1 01 83 ed 01 75 ?? 66 8b 0d ?? ?? ?? ?? 66 3b 0d ?? ?? ?? ?? 5f 5e 5d 5b 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_DN_2147740746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.DN!MTB"
        threat_id = "2147740746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 da 83 c2 10 33 c9 0f b6 99 00 ?? ?? ?? c1 e3 18 81 f3 00 00 00 ?? c1 eb 18 88 1c 01 41 3b ca 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_2147740987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos!MTB"
        threat_id = "2147740987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Remcos" ascii //weight: 5
        $x_3_2 = "Error: Unable to create socket" ascii //weight: 3
        $x_5_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall" ascii //weight: 5
        $x_5_4 = "TLS13-AES128-GCM-SHA256" ascii //weight: 5
        $x_2_5 = "status audio mode" ascii //weight: 2
        $x_1_6 = "connection reset" ascii //weight: 1
        $x_1_7 = "Mutex_RemWatchdog" ascii //weight: 1
        $x_1_8 = "SHDeleteKeyW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Remcos_A_2147742123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.A!MTB"
        threat_id = "2147742123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 8a 84 85 ?? ?? ff ff 8b 55 ?? 30 04 3a 47 4b 0f 85 ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 fc 8a 04 38 8b 55 e8 88 04 3a 47 4b 75 f0}  //weight: 1, accuracy: High
        $x_1_3 = {89 38 47 83 c0 04 81 ff 00 01 00 00 75 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_A_2147742123_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.A!MTB"
        threat_id = "2147742123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SHELLEXECUTE ( \"schtasks\" , \"/create /tn \" & $REGKEY & \" /tr" ascii //weight: 2
        $x_2_2 = "DLLCALL ( \"urlmon.dll\" , \"ptr\" , \"URLDownloadToFile\"" ascii //weight: 2
        $x_2_3 = "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command" ascii //weight: 2
        $x_2_4 = "FILEEXISTS ( @HOMEDRIVE & \"\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegAsm.exe" ascii //weight: 2
        $x_2_5 = "DLLCALL ( \"kernel32.dll\" , \"handle\" , \"CreateMutexW" ascii //weight: 2
        $x_2_6 = "EXECUTE ( \"DllStructCreate\" ) , EXECUTE ( \"DllCall\" ) , EXECUTE ( \"DllCallAddress\" )" ascii //weight: 2
        $x_2_7 = "Set WshShell = WScript.CreateObject" ascii //weight: 2
        $x_2_8 = "( $RESNAME , $FILENAME , $RUN , $RUNONCE , $DIR )" ascii //weight: 2
        $x_2_9 = "byte shellcode[" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_PB_2147743130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.PB!MTB"
        threat_id = "2147743130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b c1 c1 e8 10 30 04 3e 46 3b f2 7c e7}  //weight: 5, accuracy: High
        $x_5_2 = {8a 44 19 02 8a 4c 19 03 88 85 ?? ?? ?? ?? 8a d1 a1 ?? ?? ?? ?? 80 e2 f0 c0 e2 02 88 8d ?? ?? ?? ?? 0a 14 18 81 3d ?? ?? ?? ?? ?? ?? 00 00 88 95 ?? ?? ?? ?? 0f 84 ?? ?? ?? 00 8a d1 80 e2 fc c0 e2 04 0a 54 18 01 a1 ?? ?? ?? ?? 88 95}  //weight: 5, accuracy: Low
        $x_5_3 = {05 c3 9e 26 00 a3 ?? ?? ?? ?? c1 e8 10 25 ff 7f 00 00 c3 0a 00 69 05 ?? ?? ?? ?? fd 43 03 00}  //weight: 5, accuracy: Low
        $x_5_4 = {8a 42 02 88 44 24 ?? 8a 42 03 8a f8 88 44 24 ?? 80 e7 f0 c0 e7 02 0a 3a 81 f9 ?? ?? 00 00 0f 84 ?? ?? ?? ?? 8a d8 80 e3 fc c0 e3 04 0a 5a 01 83 f9 ?? 75}  //weight: 5, accuracy: Low
        $x_1_5 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Remcos_SD_2147743621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.SD!!Remcos.gen!SD"
        threat_id = "2147743621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "Remcos: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "SD: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Offline Keylogger" ascii //weight: 1
        $x_1_2 = "Screenshots" ascii //weight: 1
        $x_1_3 = "MicRecords" ascii //weight: 1
        $x_1_4 = "remcos" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_DSK_2147743753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.DSK!MTB"
        threat_id = "2147743753"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 7c 24 24 8a 54 24 14 8a 44 24 16 0a 44 24 12 88 14 3e 83 25 ?? ?? ?? ?? 00 8a 54 24 15 88 54 3e 01 81 3d ?? ?? ?? ?? d8 01 00 00 88 44 24 16 75}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 54 24 15 33 c9 8a 44 24 17 0a 44 24 13 88 14 3e 8a 54 24 16 89 0d ?? ?? ?? ?? 88 54 3e 01 81 3d ?? ?? ?? ?? d8 01 00 00 88 44 24 17 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Remcos_SE_2147744892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.SE"
        threat_id = "2147744892"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Uploading file to C&C" ascii //weight: 1
        $x_1_2 = "Offline Keylogger Started" ascii //weight: 1
        $x_1_3 = "Offline Keylogger Stopped" ascii //weight: 1
        $x_1_4 = "[Following text has been pasted from clipboard:]" ascii //weight: 1
        $x_1_5 = "[Firefox StoredLogins cleared!]" ascii //weight: 1
        $x_1_6 = "[IE cookies not found]" ascii //weight: 1
        $x_1_7 = "MicRecords" ascii //weight: 1
        $x_1_8 = "Remcos" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Remcos_SE_2147744894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.SE!!Remcos.gen!SD"
        threat_id = "2147744894"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "Remcos: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "SD: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Uploading file to C&C" ascii //weight: 1
        $x_1_2 = "Offline Keylogger Started" ascii //weight: 1
        $x_1_3 = "Offline Keylogger Stopped" ascii //weight: 1
        $x_1_4 = "[Following text has been pasted from clipboard:]" ascii //weight: 1
        $x_1_5 = "[Firefox StoredLogins cleared!]" ascii //weight: 1
        $x_1_6 = "[IE cookies not found]" ascii //weight: 1
        $x_1_7 = "MicRecords" ascii //weight: 1
        $x_1_8 = "Remcos" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Remcos_RO_2147745739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.RO!MTB"
        threat_id = "2147745739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 0a 34 ?? 04 ?? 34 ?? 2c ?? 88 01 41 83 ee 01 75 ?? 68 de c0 ad de}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 04 0a 34 ?? 2c ?? 34 ?? 2c ?? 88 01 41 83 ee 01 75 ?? 68 de c0 ad de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Remcos_RO_2147745739_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.RO!MTB"
        threat_id = "2147745739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 db 66 81 fb ee 00 ff 37 83 ff ?? 66 83 fa ?? 66 81 fa ?? ?? 66 83 fb ?? 85 d2 81 fb ?? ?? ?? ?? 5f 66 81 fb ?? ?? 66 a9 ?? ?? 81 ff ?? ?? ?? ?? 66 3d ?? ?? 66 85 d2 83 f8 ?? 66 85 d2 66 83 ff ?? 31 f7 66 83 fa ?? 66 85 d2 81 fa ?? ?? ?? ?? 83 ff ?? 66 83 f8 ?? 85 c0 89 3c 10 85 c0 85 db}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_RS_2147747843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.RS!MTB"
        threat_id = "2147747843"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c7 dc ac 6d 01 89 39 0f b6 15 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? b9 01 00 00 00 3b d5 76 ?? fe 05 ?? ?? ?? ?? 8d 74 2e 2b 83 44 24 10 04 29 4c 24 14 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_G_2147748026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.G!MTB"
        threat_id = "2147748026"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 04 24 65 8b d3 [0-1] 8b fe 03 fa 8a 90 [0-4] [0-2] 32 14 24 88 17 40 40 [0-2] 43 81 fb 66 5e 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_RVL_2147749830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.RVL!MTB"
        threat_id = "2147749830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "RRZLPXDCULQJIKORIBKDBSE" ascii //weight: 1
        $x_1_2 = {c7 45 fc da 93 1f 38 33 c0 8b c8 83 e1 03 8a 4c 0d f8 30 4c 05 fc 40 83 f8 04}  //weight: 1, accuracy: High
        $x_1_3 = {8b c8 83 e1 03 8a 4c 0d f8 30 88 ?? ?? ?? ?? 40 3d 05 5c 00 00 72 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_PFD_2147749994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.PFD!MTB"
        threat_id = "2147749994"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 0c 8b 45 f8 8b 14 81 8b 4d fc 33 14 8d ?? ?? ?? ?? 8b 45 08 8b 4d f8 89 14 88 83 7d fc ?? 75 ?? 33 d2 89 55 fc ff 45 f8 ff 45 fc 8b 45 f8 3b 45 10 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_JFY_2147750725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.JFY!MTB"
        threat_id = "2147750725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 1c 17 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 f3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 1c 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c2 04}  //weight: 5, accuracy: Low
        $x_10_2 = "Z5zLsZeWKW8cithRjMzu4ON7xuK146" wide //weight: 10
        $x_10_3 = "s60MfRFb0UOcVueFwUAZGj1Z0Fc1q2rsX9b56" wide //weight: 10
        $x_5_4 = "cae3PdAJIZ9D39" wide //weight: 5
        $x_10_5 = "LEoCwf77eHev1FEFC0wGYWZF8mfBqmLC229" wide //weight: 10
        $x_5_6 = "ipIJ5khkM33u0qZJiHVV8hd9gGQUi59" wide //weight: 5
        $x_10_7 = "T0ChthUlO1I3xA49WsyKlUnYTUJ4pe192" wide //weight: 10
        $x_5_8 = "MeJ63ZW93" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Remcos_AA_2147750878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.AA!MTB"
        threat_id = "2147750878"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zdvT_i1jso3v7MtW0/es.uugu.a//:sptth" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_AA_2147750878_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.AA!MTB"
        threat_id = "2147750878"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 a8 3b 45 a4 ?? ?? ?? 8b 45 a4 31 45 a8 8b 45 a8 31 45 a4 8b 45 a4 31 45 a8 6a 04 68 00 10 00 00 8b 45 a8 03 45 b0 50}  //weight: 2, accuracy: Low
        $x_2_2 = {81 c2 a1 03 00 00 87 d1 29 d3 33 c0 5a 59 59 64 89 10 68 6e 80 46 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_AA_2147750878_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.AA!MTB"
        threat_id = "2147750878"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gdead/dead-lyrics/" ascii //weight: 1
        $x_1_2 = "China_Cat_Sunflower.txt" ascii //weight: 1
        $x_1_3 = "\\shell\\open\\command" ascii //weight: 1
        $x_1_4 = "OpenAs_RunDLL" ascii //weight: 1
        $x_1_5 = "OpenClipboard" ascii //weight: 1
        $x_1_6 = "GetCapture" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_VB_2147751278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.VB!MTB"
        threat_id = "2147751278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d2 02 00 cc d2 02 00 da d2 02 00 e8 d2 02 00 fa d2 02 00 08 d3 02 00 1c d3 02 00 32 d3 02 00 3c d3 02 00 58 d3 02 00 6e d3 02 00 7c d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_RRR_2147751434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.RRR!MTB"
        threat_id = "2147751434"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 1c 17 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 f3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 1c 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c2 04}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 1c 17 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 f3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 1c 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c2 04}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 1c 17 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 f3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 1c 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c2 04}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 1c 17 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 f3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 1c 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c2 04}  //weight: 1, accuracy: Low
        $x_1_5 = {ff 34 17 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 f3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 1c 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c2 04}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 1c 17 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 f3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 1c 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c2 04}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 1c 17 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 f3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 1c 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c2 04}  //weight: 1, accuracy: Low
        $x_1_8 = {8b 1c 17 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 f3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 1c 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c2 04}  //weight: 1, accuracy: Low
        $x_1_9 = {8b 1c 17 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 f3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 1c 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c2 04}  //weight: 1, accuracy: Low
        $x_1_10 = {8b 1c 17 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 f3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 1c 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c2 04}  //weight: 1, accuracy: Low
        $x_1_11 = {8b 1c 17 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 f3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 1c 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c2 04}  //weight: 1, accuracy: Low
        $x_1_12 = {8b 1c 17 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 f3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 1c 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c2 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Remcos_ACJ_2147751748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.ACJ!MTB"
        threat_id = "2147751748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 8b 1c 0e ef 00 b9 ?? ?? 00 00 [0-31] 90 [0-79] 31 ff [0-31] 90 [0-31] 31 c7}  //weight: 1, accuracy: Low
        $x_1_2 = {66 09 1c 0f 3f 00 51 59 [0-31] 90}  //weight: 1, accuracy: Low
        $x_1_3 = {51 59 51 59 [0-31] ff e0 [0-47] 81 34 08 ?? ?? ?? ?? 90}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_RGU_2147751786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.RGU!MTB"
        threat_id = "2147751786"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 0c 90 8b 45 14 8b 55 fc 33 0c 90 8b 45 08 8b 55 f8 89 0c 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_RN_2147753374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.RN!MTB"
        threat_id = "2147753374"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 30 ff 77 ?? 68 ?? ?? ?? ?? 81 04 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 81 04 24 ?? ?? ?? ?? ff d0 68 ?? ?? ?? ?? 5a b9 ?? ?? ?? ?? 8b 1c 0a 81 f3 ?? ?? ?? ?? 89 1c 08 83 e9 ?? 7d ?? ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_RD_2147753376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.RD!MTB"
        threat_id = "2147753376"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 85 c0 83 f6 ?? 8b 1c 0f 66 3d ?? ?? 66 3d ?? ?? 66 3d ?? ?? 83 f6 ?? 83 f6 ?? 66 3d ?? ?? 66 3d ?? ?? 66 3d ?? ?? 31 c3 66 3d ?? ?? 83 f6 ?? 66 3d ?? ?? 83 f6 ?? 85 c0 83 f6 ?? 53 83 f6 ?? 85 c0 66 3d ?? ?? 83 f6 ?? 8f 04 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_RJ_2147753377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.RJ!MTB"
        threat_id = "2147753377"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 85 c0 89 0c 18 85 db 66 85 ff 4b 66 85 c0 85 c9 4b 85 c0 66 85 c0 4b 85 db 85 c9 4b 7d ?? 85 db 85 c9 ff e0 [0-4] 81 f1 ?? ?? ?? ?? 85 c9 66 85 ff c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_CL_2147753964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.CL!MTB"
        threat_id = "2147753964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 fc 3b 45 10 ?? ?? 8b 4d f8 03 4d fc 8b 55 f4 03 55 fc 8a 02 88 01 eb}  //weight: 10, accuracy: Low
        $x_1_2 = "tamagochi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_CZ_2147753965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.CZ!MTB"
        threat_id = "2147753965"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a c8 66 be 48 11 bb ?? ?? ?? ?? d3 c3 8d b4 05 ec fe ff ff c1 d1 ?? 8d 0c 18 f9 32 0c 37 88 0e 0f}  //weight: 5, accuracy: Low
        $x_3_2 = "GlobalLock" ascii //weight: 3
        $x_2_3 = "OpenClipboard" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_PR_2147754498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.PR!MTB"
        threat_id = "2147754498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5a b9 e0 d4 00 00 8b 1c 0a 81 f3 ?? ?? ?? ?? 89 1c 08 83 e9 ?? 7d ?? ff ?? e2 ?? 99}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_PI_2147754508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.PI!MTB"
        threat_id = "2147754508"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Test.thg" ascii //weight: 1
        $x_1_2 = {53 31 db 8b 04 8a 88 c7 88 e3 c1 e8 10 c1 e3 08 88 c3 89 1c 8a 49 79 ?? 5b 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c8 8b 44 24 ?? 8b 50 ?? 03 d6 8b 44 24 ?? 8b 40 ?? 03 44 24 ?? e8 da d2 f8 ff 8b 44 24 ?? 8b 40 ?? 03 44 24 ?? 8b 54 24 ?? 89 42 ?? 8b 44 24 ?? 83 c0 ?? 89 44 24 ?? 4b 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_PVA_2147755703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.PVA!MTB"
        threat_id = "2147755703"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 5c 1d fc 30 58 03 0f b6 1f 30 58 04 83 c1 05 83 c6 05 81 f9 05 5a 00 00 72}  //weight: 2, accuracy: High
        $x_2_2 = {8b c8 83 e1 03 8a 4c 0d f8 30 8c 05 ?? ?? ff ff 40 3d 05 5a 00 00 72}  //weight: 2, accuracy: Low
        $x_1_3 = "ZYGMBVCJJWBUZUXPNDHWHDHAZJKUOMKFCVYJCLYWAHQUEZOAU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Remcos_BA_2147756570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.BA!MTB"
        threat_id = "2147756570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 5d 08 8b c6 99 f7 f9 8a 04 1a 8b 55 f8 30 04 16 46 3b f7 7c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_BA_2147756570_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.BA!MTB"
        threat_id = "2147756570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 89 45 ?? 8b 4d ?? 3b 8d ?? ?? ff ff 7d ?? 8b 45 ?? 99 f7 bd ?? ?? ff ff 8b 85 ?? ?? ff ff 0f be 0c 10 8b 95 ?? ?? ff ff 03 55 ?? 0f be 02 33 c1 8b 8d ?? ?? ff ff 03 4d ?? 88 01 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 85 30 ff ff ff c6 85 ?? ?? ff ff c6 85 ?? ?? ff ff c6 85 ?? ?? ff ff c6 85 ?? ?? ff ff c6 85 ?? ?? ff ff c6 85 ?? ?? ff ff c6 85 ?? ?? ff ff c6 85 ?? ?? ff ff c6 85 ?? ?? ff ff c6 85 ?? ?? ff ff c6 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 85 74 fe ff ff c6 85 ?? ?? ff ff c6 85 ?? ?? ff ff c6 85 ?? ?? ff ff c6 85 ?? ?? ff ff c6 85 ?? ?? ff ff c6 85 ?? ?? ff ff c6 85 ?? ?? ff ff c6 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_BB_2147756574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.BB!MTB"
        threat_id = "2147756574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 a1 ?? ?? ?? ?? 8b 08 8b 15 ?? ?? ?? ?? 8b 04 91 2d ?? ?? ?? ?? 89 45 fc 8b 0d ?? ?? ?? ?? 83 c1 01 89 0d ?? ?? ?? ?? 8b 45 fc 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 44 24 2a 33 66 c7 44 24 ?? 6b 65 c6 44 24 ?? 00 c6 44 24 ?? 56 c6 44 24 ?? 74 c6 44 24 ?? 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {2b d0 33 05 ?? ?? ?? ?? c6 44 24 ?? 6e c6 44 24 ?? 32 c6 44 24 ?? 6f c6 44 24 ?? 75 3b c2 7f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_BC_2147756855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.BC!MTB"
        threat_id = "2147756855"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 a1 ?? ?? ?? ?? 8b 08 8b 15 ?? ?? ?? ?? 8b 04 91 2d ?? ?? ?? 00 89 45 fc 8b 0d ?? ?? ?? ?? 83 c1 01 89 0d ?? ?? ?? ?? 8b 45 fc 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d7 8d 54 24 10 8b f8 33 f6 89 15 ?? ?? ?? ?? b3 ?? e8 ?? ?? ff ff 0f bf 0d ?? ?? ?? ?? 39 0d ?? ?? ?? ?? 7c ?? 88 1d ?? ?? ?? ?? 88 04 3e 83 c6 01 81 fe ?? ?? 00 00 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {6e c6 44 24 ?? 32 c6 44 24 ?? 6f c6 44 24 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_BD_2147757581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.BD!MTB"
        threat_id = "2147757581"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8b ec 51 a1 ?? ?? ?? ?? 8b 08 8b 15 ?? ?? ?? ?? 8b 04 91 2d ?? ?? ?? 00 89 45 fc 8b 0d ?? ?? ?? ?? 83 c1 01 89 0d ?? ?? ?? ?? 8b 45 fc 8b e5 5d c3}  //weight: 2, accuracy: Low
        $x_1_2 = {83 c0 01 89 45 ?? 8b 4d ?? 3b 4d ?? 7d ?? e8 ?? ?? 00 00 89 45 ?? 8b 4d ?? 03 4d ?? 8a 55 ?? 88 11 83 3d ?? ?? ?? ?? 00 74 ?? 83 3d ?? ?? ?? ?? 00 74 ?? b8 04 00 00 00 d1 e0 c7 80 ?? ?? ?? ?? ?? 00 00 00 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_BE_2147757751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.BE!MTB"
        threat_id = "2147757751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c1 01 89 4d ?? 8b 55 ?? 3b 55 ?? 7d ?? e8 ?? ?? ff ff 89 45 ?? 8b 4d ?? 03 4d ?? 8a 55 ?? 88 11 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {65 c7 45 f8 ?? ?? ?? ?? c6 45 ?? 6c c6 45 ?? 6e c6 45 ?? 32 c6 45 ?? 6f c6 45 ?? 75}  //weight: 1, accuracy: Low
        $x_2_3 = {55 8b ec 51 a1 ?? ?? ?? ?? 8b 08 8b 15 ?? ?? ?? ?? 8b 04 91 2d ?? ?? ?? 00 89 45 fc 8b 0d ?? ?? ?? ?? 83 c1 01 89 0d ?? ?? ?? ?? 8b 45 fc 8b e5 5d c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_DSA_2147760524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.DSA!MTB"
        threat_id = "2147760524"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 8d 0c 06 e8 ?? ?? ?? ?? 30 01 46 3b 75 0c 7c 06 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? c1 e8 10 25 ff 7f 00 00 05 00 a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_SM_2147763558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.SM!MTB"
        threat_id = "2147763558"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "3b111b404a0b7c4a0c54571f370c1c53564337041f4017523c0840514d453206075d5c5f271640070c006b525f090a066452560008006550561f0e0461515e040c0861515702010160525b02167e21081b444d45" ascii //weight: 1
        $x_1_2 = "3b111b404a0b7c4a0c54571f370c1c53564337041f4017523c0840514d453206075d5c5f271640070c006b525f090a066452560008006550561f0e0461515e03080762545e030c006b5556001669311f06595058" ascii //weight: 1
        $x_1_3 = "3b111b404a0b7c4a0c54571f370c1c53564337041f4017523c0840514d453206075d5c5f271640070c006b525f090a066452560008006550561f0e0461515e01000662515b090c0363575e08166b300f1a454c44" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Remcos_ACH_2147763919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.ACH!MTB"
        threat_id = "2147763919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {31 07 8b 07 31 05 ?? ?? ?? ?? a1 00 31 07 6a 04 68 00 10 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_ACH_2147763919_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.ACH!MTB"
        threat_id = "2147763919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {31 07 8b 07 31 05 ?? ?? ?? ?? a1 00 31 07 6a 04 68 00 10 00 00}  //weight: 5, accuracy: Low
        $x_1_2 = "C:\\Users\\Yak\\Desktop\\Alt_R66Draw\\T___imgFig.pas" ascii //weight: 1
        $x_1_3 = "C:\\Users\\Yak\\Desktop\\Alt_R66Draw\\T__RGroup.pas" ascii //weight: 1
        $x_1_4 = "C:\\Users\\Yak\\Desktop\\Alt_R66Draw\\T__RUndo.pas" ascii //weight: 1
        $x_1_5 = "C:\\Users\\Yak\\Desktop\\Alt_R66Draw\\T__RSelFrm.pas" ascii //weight: 1
        $x_1_6 = "C:\\Users\\Yak\\Desktop\\Alt_R66Draw\\T__RCore.pas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_DD_2147772209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.DD!MTB"
        threat_id = "2147772209"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\AppData\\Roaming\\remcos\\" ascii //weight: 1
        $x_1_2 = "\\AppData\\Roaming\\Screenshots\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_ZB_2147773172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.ZB!MTB"
        threat_id = "2147773172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 8b c6 5a 8b ca 99 f7 f9 42 8b 45 f8 8a 44 10 ff 32 c3 8b d8 8d 45 e8}  //weight: 1, accuracy: High
        $x_1_2 = "XE33Mes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_ZC_2147773446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.ZC!MTB"
        threat_id = "2147773446"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5a 8b ca 99 f7 f9 42 8b 45 f8 8a 44 10 ff 32 ?? ?? ?? 8d 45}  //weight: 5, accuracy: Low
        $x_1_2 = "seM33EX" ascii //weight: 1
        $x_1_3 = "XE33Mes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Remcos_ZF_2147773990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.ZF!MTB"
        threat_id = "2147773990"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 10 c7 45 f8 00 00 00 00 e8 4e ff ff ff c7 45 f8 00 00 00 00 eb 09 8b 45 f8 83 c0 01 89 45 f8 81 7d f8 ?? ?? ?? ?? 0f 83}  //weight: 1, accuracy: Low
        $x_1_2 = {68 3e 50 b3 93 68 ?? ?? ?? ?? ff 15 44 b0 00 10 50 e8 ?? ?? ?? ?? 83 c4 08 89 45 f4 8d ?? ?? ?? 6a 40 68 ?? ?? ?? ?? 68 a0 d6 00 10 ff 55 f4 8b ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c4 04 8b e5 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_ZEE_2147774330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.ZEE!MTB"
        threat_id = "2147774330"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5a 8b ca 99 f7 f9 42 8b 45 f8 8a 44 10 ff 32 ?? ?? ?? 8d 45}  //weight: 10, accuracy: Low
        $x_10_2 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_1_3 = "cdn.discordapp.com" ascii //weight: 1
        $x_1_4 = "C:\\Users\\Public\\Libraries\\TEMP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Remcos_ZG_2147775612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.ZG!MTB"
        threat_id = "2147775612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 10 c7 45 f8 00 00 00 00 e8 ?? ?? ?? ?? c7 45 f8 00 00 00 00 eb 09 8b 45 f8 83 c0 01 89 45 f8 81 7d f8 ?? ?? ?? ?? 0f 83}  //weight: 1, accuracy: Low
        $x_1_2 = {68 3e 50 b3 93 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 08 89 45 f4 8d ?? ?? ?? 6a 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 55 f4 8b ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c4 04 8b e5 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_ZI_2147775974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.ZI!MTB"
        threat_id = "2147775974"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5a 8b ca 99 f7 f9 42 [0-5] 8a 44 50 fe 32 07 88 07 8d 45 f0 8a 17 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_EA_2147778773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.EA!MTB"
        threat_id = "2147778773"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 9c 07 49 9e 00 00 88 1c 30 81 f9 8d 00 00 00 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_AB_2147781974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.AB!MTB"
        threat_id = "2147781974"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 19 46 33 de 3b df 75 f6}  //weight: 10, accuracy: High
        $x_3_2 = "srblzbcikl" ascii //weight: 3
        $x_3_3 = "kythdigul" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_AG_2147782000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.AG!MTB"
        threat_id = "2147782000"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 19 46 33 de 3b df 75 ?? 89 b4 95 ?? ?? ?? ?? 42 41 81 fa ff 01 00 00 72}  //weight: 1, accuracy: Low
        $x_1_2 = {30 14 08 05 ff 01 00 00 3b c6 7c ?? 47 81 ff ff 01 00 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_B_2147782015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.B!MTB"
        threat_id = "2147782015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {55 8b ec 81 ec 9c 00 00 00 56 57 68 00 08 00 00 68 00 30 00 10 b8 00 a2 07 10 e8}  //weight: 10, accuracy: High
        $x_3_2 = "dfgh7fd54hfd5h4" ascii //weight: 3
        $x_3_3 = "kythdigul9f" ascii //weight: 3
        $x_3_4 = "kythdigulf2" ascii //weight: 3
        $x_3_5 = "kythdigulf3" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_ET_2147784160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.ET!MTB"
        threat_id = "2147784160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = "Ixkdoc" ascii //weight: 20
        $x_20_2 = "Hfkeoc" ascii //weight: 20
        $x_20_3 = "diejc.dll" ascii //weight: 20
        $x_1_4 = {43 3a 5c 54 45 4d 50 5c 6e 73 ?? ?? ?? ?? ?? 2e 74 6d 70}  //weight: 1, accuracy: Low
        $x_1_5 = "NullsoftInst" ascii //weight: 1
        $x_1_6 = "GetTempFileNameA" ascii //weight: 1
        $x_1_7 = "FindFirstFileA" ascii //weight: 1
        $x_1_8 = "DeleteFileA" ascii //weight: 1
        $x_1_9 = "Delete on reboot" ascii //weight: 1
        $x_1_10 = "ExecShell" ascii //weight: 1
        $x_1_11 = "%s%s.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 8 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Remcos_AUT_2147788931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.AUT!MTB"
        threat_id = "2147788931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 a4 e9 17 03 00 00 81 f9 80 00 00 00 0f 82 ce 01 00 00 57 58 33 c6 a9 0f ?? ?? ?? 75 0e 0f ba 25 ?? ?? ?? ?? 01 0f 82 da 04 00 00 0f ba 25 ?? ?? ?? ?? 00 0f 83 a7 01 00 00 f7 c7 03 ?? ?? ?? 0f 85 b8 01 00 00 f7 c6 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_HYTG_2147795827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.HYTG!MTB"
        threat_id = "2147795827"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff cc 31 00 02 6b be 00 20 ab 86 0c 44 b3 c3}  //weight: 1, accuracy: High
        $x_1_2 = {22 71 81 32 06 14 91}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_FS_2147796547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.FS!MTB"
        threat_id = "2147796547"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 75 eb 89 f0 05 9d 00 00 00 88 45 eb 0f b6 75 eb c1 fe 05 0f b6 7d eb c1 e7 03 89 f0 09 f8 88 45 eb 8b 75 ec 0f b6 7d eb 89 f8 29 f0 88 45 eb 8a 45 eb 8b 75 ec 88 04 35 ?? ?? ?? ?? 8b 45 ec 83 c0 01 89 45 ec e9}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 75 eb 29 f0 88 45 eb 0f b6 75 eb 89 f0 35 ff 00 00 00 88 45 eb 8b 75 ec 0f b6 7d eb 89 f8 29 f0 88 45 eb 0f b6 75 eb 89 f0 83 f0 ff 88 45 eb 8a 45 eb 8b 75 ec 88 04 35 ?? ?? ?? ?? 8b 45 ec 83 c0 01 89 45 ec e9}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 7d eb c1 e7 07 89 f0 09 f8 88 45 eb 0f b6 75 eb 89 f0 83 e8 39 88 45 eb 0f b6 75 eb 89 f0 83 f0 59 88 45 eb 8b 75 ec 0f b6 7d eb 89 f8 29 f0 88 45 eb 0f b6 75 eb 89 f0 35 85 00 00 00 88 45 eb 8a 45 eb 8b 75 ec 88 04 35 ?? ?? ?? ?? 8b 45 ec 83 c0 01 89 45 ec e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Remcos_AD_2147797469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.AD!MTB"
        threat_id = "2147797469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "commdlg_FindReplace" ascii //weight: 3
        $x_3_2 = "HelpKeyword" ascii //weight: 3
        $x_3_3 = "Mqypdx\\egc" ascii //weight: 3
        $x_3_4 = "DWE78PmQW_bghg" ascii //weight: 3
        $x_3_5 = "WinHttpCrackUrl" ascii //weight: 3
        $x_3_6 = "Ducky" ascii //weight: 3
        $x_3_7 = "Read Icon List for Delphi 3.0" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_GB_2147799397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.GB!MTB"
        threat_id = "2147799397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Adobe Photoshop" ascii //weight: 1
        $x_1_2 = "Choose signature to inject" ascii //weight: 1
        $x_1_3 = "Add new section in file" ascii //weight: 1
        $x_1_4 = "Write code in new section" ascii //weight: 1
        $x_1_5 = "WinHttpCrackUrl" ascii //weight: 1
        $x_1_6 = "GetClipboardData" ascii //weight: 1
        $x_1_7 = "Armadillo" ascii //weight: 1
        $x_1_8 = "DAEMON Protect" ascii //weight: 1
        $x_1_9 = "PE-SHiELD" ascii //weight: 1
        $x_1_10 = "JDPack" ascii //weight: 1
        $x_1_11 = "nSpack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_GI_2147805555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.GI!MTB"
        threat_id = "2147805555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d0 03 d2 8b 4c 24 08 8d 54 d1 04 89 54 24 04 8b 54 24 04 8b 0b 89 0a 8b 54 24 04 89 13 40 83 f8 64}  //weight: 1, accuracy: High
        $x_1_2 = {44 00 56 00 43 00 4c 00 41 00 4c}  //weight: 1, accuracy: High
        $x_1_3 = {48 00 41 00 4e 00 41 00 4d 00 53 00 49 00 4f}  //weight: 1, accuracy: High
        $x_1_4 = "RTLConsts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_GJ_2147807319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.GJ!MTB"
        threat_id = "2147807319"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 4c 24 0c 30 04 31 81 ff 91 05 00 00 75 05 00 e8}  //weight: 10, accuracy: Low
        $x_1_2 = {05 c3 9e 26 00 81 3d ?? ?? ?? ?? 81 13 00 00 a3 ?? ?? ?? ?? 0f b7 35 ?? ?? ?? ?? 75 05 00 a1}  //weight: 1, accuracy: Low
        $x_1_3 = {05 c3 9e 26 00 81 3d ?? ?? ?? ?? 81 13 00 00 56 a3 ?? ?? ?? ?? 0f b7 35 ?? ?? ?? ?? 75 05 00 a1}  //weight: 1, accuracy: Low
        $x_1_4 = {83 44 24 04 0d a1 ?? ?? ?? ?? 0f af 44 24 ?? 81 3d ?? ?? ?? ?? 9e 13 00 00 a3 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_5 = {83 04 24 04 0d a1 ?? ?? ?? ?? 0f af 04 24 ?? 81 3d ?? ?? ?? ?? 9e 13 00 00 a3 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Remcos_DDL_2147807573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.DDL!MTB"
        threat_id = "2147807573"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 00 02 04 d8 09 b0 04 bf 04 ef 01 0b 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_GP_2147807967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.GP!MTB"
        threat_id = "2147807967"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d0 03 d2 8b 4c 24 08 8d 54 d1 04 89 54 24 04 8b 54 24 04 8b 0b 89 0a 8b 54 24 04 89 13 40 83 f8 64}  //weight: 1, accuracy: High
        $x_1_2 = {44 00 56 00 43 00 4c 00 41 00 4c}  //weight: 1, accuracy: High
        $x_1_3 = {4e 00 4f 00 4d 00 53 00 49 00 4c}  //weight: 1, accuracy: High
        $x_1_4 = "RTLConsts" ascii //weight: 1
        $x_1_5 = "GetClipboardData" ascii //weight: 1
        $x_1_6 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_SIB_2147808476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.SIB!MTB"
        threat_id = "2147808476"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\\\ALA.DLL" wide //weight: 1
        $x_1_2 = {ba 01 00 00 00 a1 ?? ?? ?? ?? 8b 38 ff 57 ?? 8b 45 ?? 8b 16 0f b6 7c 10 ?? a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? ba 00 01 00 00 2b d0 52 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 5a 92 8b ca 99 f7 f9 03 fa 8b d7 8d 45 ?? e8 ?? ?? ?? ?? 8b 55 08 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 06 ff 4d ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_HF_2147811895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.HF!MTB"
        threat_id = "2147811895"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CSrSySpStSAScSqSuSiSrSeSCSoSnStSeSxStSAS" ascii //weight: 1
        $x_1_2 = "R-t-l-D-e-c-o-m-p-r-e-s-s-B-u-f-f-e-r-" ascii //weight: 1
        $x_1_3 = "V_i_r_t_u_a_l_P_r_o_t_e_c_t_" ascii //weight: 1
        $x_1_4 = "GVeVtVTViVcVkVCVoVuVnVtV" ascii //weight: 1
        $x_1_5 = "EYxYiYtYPYrYoYcYeYsYsY" ascii //weight: 1
        $x_1_6 = "C7r7y7p7t7D7e7c7r7y7p7t7" ascii //weight: 1
        $x_1_7 = "Zeta Debugger" ascii //weight: 1
        $x_1_8 = "Rock Debugger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_HL_2147813323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.HL!MTB"
        threat_id = "2147813323"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b f7 8b c7 c1 e8 02 83 e6 03 8b ce c1 e1 03 8d 34 b0 8d 04 90 ba ff 00 00 00 8b 44 83 18 d3 e2 23 c2 8b 55 fc d3 e8 30 04 1e 47 83 ff 10 7c d0}  //weight: 1, accuracy: High
        $x_1_2 = "S#q-}=6{)BuEV[GDeZy>~M5D/P&Q}7<" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_GS_2147814448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.GS!MTB"
        threat_id = "2147814448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d0 03 d2 8b 4c 24 08 8d 54 d1 04 89 54 24 04 8b 54 24 04 8b 0b 89 0a 8b 54 24 04 89 13 40 83 f8 64}  //weight: 1, accuracy: High
        $x_1_2 = {44 00 56 00 43 00 4c 00 41 00 4c}  //weight: 1, accuracy: High
        $x_1_3 = {57 00 4d 00 53 00 49 00 49 00 4e}  //weight: 1, accuracy: High
        $x_1_4 = "RTLConsts" ascii //weight: 1
        $x_1_5 = "GetClipboardData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_GT_2147814449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.GT!MTB"
        threat_id = "2147814449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d0 03 d2 8b 4c 24 08 8d 54 d1 04 89 54 24 04 8b 54 24 04 8b 0b 89 0a 8b 54 24 04 89 13 40 83 f8 64}  //weight: 1, accuracy: High
        $x_1_2 = {44 00 56 00 43 00 4c 00 41 00 4c}  //weight: 1, accuracy: High
        $x_1_3 = {4b 00 4c 00 4d 00 53 00 49 00 43}  //weight: 1, accuracy: High
        $x_1_4 = "RTLConsts" ascii //weight: 1
        $x_1_5 = "GetClipboardData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_GX_2147814450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.GX!MTB"
        threat_id = "2147814450"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 00 56 00 43 00 4c 00 41 00 4c}  //weight: 1, accuracy: High
        $x_1_2 = {48 00 41 00 4d 00 53 00 49 00 4d}  //weight: 1, accuracy: High
        $x_1_3 = {54 00 5f 00 5f 00 33 00 38 00 34 00 39 00 35 00 39 00 37 00 35 00 38 00 32}  //weight: 1, accuracy: High
        $x_1_4 = "RTLConsts" ascii //weight: 1
        $x_1_5 = "GetClipboardData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_SIBA_2147815481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.SIBA!MTB"
        threat_id = "2147815481"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Uh9OB" ascii //weight: 1
        $x_1_2 = "UhXVB" ascii //weight: 1
        $x_1_3 = "Uh2ZB" ascii //weight: 1
        $x_1_4 = {ba 01 00 00 00 a1 ?? ?? ?? ?? 8b 38 ff 57 ?? 8b 45 ?? 8b 16 0f b6 7c 10 ff b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? ba 00 01 00 00 2b d0 52 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 5a 92 8b ca 99 f7 f9 03 fa 8b d7 8d 45 ?? e8 ?? ?? ?? ?? 8b 55 07 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 06 ff 4d ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_SIBB_2147818113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.SIBB!MTB"
        threat_id = "2147818113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 85 db 7e ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 b8 ?? ?? ?? ?? 2b 45 ?? 5a 8b ca 99 f7 f9 8b 45 ?? 8b 0d ?? ?? ?? ?? 0f b6 44 08 ?? 03 d0 8d 45 ?? e8 39 0b fa ?? 8b 55 ?? 8b c6 e8 ?? ?? ?? ?? ff 05 ?? ?? ?? ?? 4b 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_MC_2147826399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.MC!MTB"
        threat_id = "2147826399"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2a c8 c0 c9 03 02 c8 d0 c1 02 c8 32 c8 2a c8 80 c1 41 c0 c9 03 80 c1 30 80 f1 d3 80 e9 18 88 88 ?? ?? ?? ?? 40 3d 05 4e 00 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_ME_2147829584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.ME!MTB"
        threat_id = "2147829584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Duck Hunt Delphi" ascii //weight: 1
        $x_1_2 = "TDuckForm" ascii //weight: 1
        $x_1_3 = "Delphi Duck Hunt" ascii //weight: 1
        $x_1_4 = "MEDIA\\GFX\\LittleDuck.bmp" ascii //weight: 1
        $x_1_5 = "MEDIA\\GFX\\GaugeKill.bmp" ascii //weight: 1
        $x_1_6 = "GetKeyboardType" ascii //weight: 1
        $x_1_7 = "DuckHunt" ascii //weight: 1
        $x_1_8 = "AddMIMEFileTypesPS" ascii //weight: 1
        $x_1_9 = ".itext" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_AIO_2147836282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.AIO!MTB"
        threat_id = "2147836282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 85 2c ff ff ff 2b 84 15 60 fb ff ff 89 85 2c ff ff ff 8b 4d e8 83 e9 01 89 4d e8 8b 95 fc fe ff ff 83 c2 01 89 95 fc fe ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_RDF_2147839820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.RDF!MTB"
        threat_id = "2147839820"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b cb ba a0 93 16 00 8a 04 19 88 03 43 4a}  //weight: 2, accuracy: High
        $x_2_2 = {8b 95 24 ff ff ff 8b c1 83 e0 1f 8a 80 ?? ?? ?? ?? 30 04 0a 41 3b cf}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_AP_2147839854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.AP!MTB"
        threat_id = "2147839854"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 64 65 6b 6e 6f 74 00 02 4f ad 33 99 66 cf 11 b7 0c 00 aa 00 60 d3 93 48 45 4d 4f 50 45 58 49 53 6b 72 6f 70 73}  //weight: 1, accuracy: High
        $x_1_2 = {42 14 b2 90 00 6c 50 c8 b5 2c 5a 12 79 e8 49 6a 77 31 24 e8 f3 7f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_RDD_2147839952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.RDD!MTB"
        threat_id = "2147839952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {30 77 da 89 57 d8 3e 9e 38 13 fc 93}  //weight: 2, accuracy: High
        $x_2_2 = {83 c4 0c 33 c0 8d 49 00 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? f7 d1 03 d1 89 94 85 58 ff ff ff 40}  //weight: 2, accuracy: Low
        $x_1_3 = "sundaymondayt.png" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_RPM_2147840233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.RPM!MTB"
        threat_id = "2147840233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 65 e8 8b 4d c8 88 4d e1 c7 45 fc fe ff ff ff 8b 5d a8 8b 75 bc 8a 45 e0 8b 7d d8 83 bd 14 01 00 00 00 75 03 8a 45 e1 88 04 39}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_GFE_2147841664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.GFE!MTB"
        threat_id = "2147841664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {1b c0 40 33 c2 03 c1 0f b7 0d ?? ?? ?? ?? 03 c8 f7 d1 66 89 4d e8 8a c3 b1 5b f6 e9 a2}  //weight: 10, accuracy: Low
        $x_10_2 = {8a 45 d4 02 d0 8b 45 b4 8b 4d b8 34 ?? f6 ea 88 45 d5}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_RPZ_2147845620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.RPZ!MTB"
        threat_id = "2147845620"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 00 31 f1 81 c1 e6 00 00 00 eb 08 28 c8 91 21 28 c8 91 21 81 e9 e6 00 00 00 81 fa ?? ?? ?? ?? 75 08 ab 03 dc f7 ab ?? ?? ?? ?? 0c 10 81 fb ?? ?? ?? ?? 75 08 c0 f9 e4 6c c0 f9 e4 6c 81 fa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_RPX_2147845882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.RPX!MTB"
        threat_id = "2147845882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f4 8b 4d f8 8d 14 30 8b 45 fc d3 ee 8b 4d d0 03 c1 33 c2 03 75 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_RPX_2147845882_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.RPX!MTB"
        threat_id = "2147845882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 8d 1c ff ff ff 83 c1 01 89 8d 1c ff ff ff 8b 95 1c ff ff ff 3b 55 0c 73 2d 8b 85 1c ff ff ff 33 d2 f7 75 14 8b 45 10 0f b6 0c 10 8b 55 08 03 95 1c ff ff ff 0f b6 02 2b c1 8b 4d 08 03 8d 1c ff ff ff 88 01 eb b9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_RPX_2147845882_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.RPX!MTB"
        threat_id = "2147845882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5b 0f b6 8d 52 fc ff ff 8b 95 68 f8 ff ff 0f be 02 2b c1 8b 8d 68 f8 ff ff 88 01 eb 95 8b 95 4c f5 ff ff 89 95 20 e6 ff ff 8d 85 18 f3 ff ff 50 8b 8d 18 f3 ff ff 51 8b 95 6c e9 ff ff 52 8b 85 18 fc ff ff 50 ff 95 20 e6 ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_AN_2147847259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.AN!MTB"
        threat_id = "2147847259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 7b 0c 8b ce e8 a5 ff ff ff 8b cb 8b f0 e8 9c ff ff ff 8b 4d fc 33 f0 23 f1 31 34 97 42}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_ARC_2147851147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.ARC!MTB"
        threat_id = "2147851147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 10 85 d2 76 15 55 a1 ?? ?? ?? ?? 03 f2 50 56 57 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_ARM_2147894535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.ARM!MTB"
        threat_id = "2147894535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 04 8d a0 01 43 00 8b f0 81 e6 ff 00 00 00 c1 e8 08 33 04 b5 a0 05 43 00 41 89 04 8d 9c 05 43 00 3b ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_ARM_2147894535_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.ARM!MTB"
        threat_id = "2147894535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {86 0e 0a 01 01 b9 6c 01 01 01 67 8a 86 e9 e7 00 00 ba 66 01 01 01 67 8a 8e eb e7 00 00 bb 73 01 01 01 67 8a 96 ed e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_ARM_2147894535_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.ARM!MTB"
        threat_id = "2147894535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 03 5d a4 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 d4 31 18 83 45 ec 04 6a 00 e8 ?? ?? ?? ?? 83 c0 04 01 45 d4 8b 45 ec 3b 45 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_ARM_2147894535_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.ARM!MTB"
        threat_id = "2147894535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0d 54 5f 5f 33 36 34 37 39 35 33 38 31 39 80 03 00 00 02 00 0d 54 5f 5f 33 36 34 37 39 36 32 35 37 30 84 03 00 00 02 00 0d 54 5f 5f 33}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_ARM_2147894535_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.ARM!MTB"
        threat_id = "2147894535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 f0 8b 44 24 20 8b d0 03 f7 0b 54 24 24 23 54 24 28 23 44 24 24 0b d0 03 d6 8b 44 24 30 8b 74 24 14 83 c0 20 89 44 24 30 3d 00 01 00 00 8b 44 24 10 89 54 24 2c 89 54 24 34}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_ARM_2147894535_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.ARM!MTB"
        threat_id = "2147894535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 07 8b 4f f8 05 ?? ?? ?? ?? 03 4d e8 6a 00 ff 77 fc 50 51 53 ff d6 8b 45 e4 8d 7f 28 8b 4d e0 41}  //weight: 1, accuracy: Low
        $x_1_2 = {03 02 03 f0 c7 45 f8 ?? ?? ?? ?? 8d 45 ec 50 6a 04 8d 45 f8 50 56 ff 75 d4 ff 15 ?? ?? ?? ?? 8b 45 c4 01 45 f8 8d 45 f8 6a 00 6a 04 50 56 ff 75 d4 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_MBEP_2147895961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.MBEP!MTB"
        threat_id = "2147895961"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d4 25 40 00 1a f9 70 01 00 ff ff ff 08 00 00 00 01 00 00 00 03 00 00 00 e9 00 00 00 e4 24 40 00 20 24 40 00 30 12 40 00 78 00 00 00 8c}  //weight: 1, accuracy: High
        $x_1_2 = {42 61 72 6d 68 6a 65 72 74 69 67 68 65 64 65 72 6e 65 33 00 53 6f 6e 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_AGLS_2147895977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.AGLS!MTB"
        threat_id = "2147895977"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 dc 03 55 b4 8b 45 d4 03 45 b0 8b 4d c0 e8 ?? ?? ?? ?? 8b 45 c0 01 45 b0 8b 45 c0 01 45 b4 8b 45 bc 01 45 b4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_EM_2147896367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.EM!MTB"
        threat_id = "2147896367"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "geoplugin.net/json.gp" ascii //weight: 1
        $x_1_2 = "sysinfo.txt" ascii //weight: 1
        $x_1_3 = "Elevation:Administrator!new:" ascii //weight: 1
        $x_1_4 = "update.vbs" ascii //weight: 1
        $x_1_5 = "fso.DeleteFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_ARS_2147897142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.ARS!MTB"
        threat_id = "2147897142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {95 07 49 68 52 05 8c 59 05 f9 36 6a f6 83 79 29 6b 35 48 69 81 35 49}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_MA_2147897367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.MA!MTB"
        threat_id = "2147897367"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 ee 04 89 74 24 ?? 31 ff 8b 74 24 ?? 8b 5d ?? 89 f8 c1 e0 ?? 03 44 24 ?? 31 c9 8a 54 0c 20 32 14 0e 88 14 0b 41 83 f9 ?? 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_LKV_2147897409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.LKV!MTB"
        threat_id = "2147897409"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 0c 1a 32 8c 05 ?? ?? ff ff 8b 85 ?? ?? ff ff 88 0c 18 43 89 f8 39 9d ?? ?? ff ff 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 84 35 ?? ?? ff ff 88 84 3d ?? ?? ff ff 8b 85 ?? ?? ff ff 88 84 35 ?? ?? ff ff 47 89 f1 81 ff ?? ?? 00 00 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Remcos_GV_2147899397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.GV!MTB"
        threat_id = "2147899397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 00 56 00 43 00 4c 00 41 00 4c}  //weight: 1, accuracy: High
        $x_1_2 = {37 00 36 00 39 00 30 00 38 00 39 00 37 00 32 00 31}  //weight: 1, accuracy: High
        $x_1_3 = {57 00 48 00 41 00 4d 00 4d 00 53 00 49 00 4f 00 4e}  //weight: 1, accuracy: High
        $x_1_4 = "RTLConsts" ascii //weight: 1
        $x_1_5 = "GetClipboardData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_ARE_2147900189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.ARE!MTB"
        threat_id = "2147900189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c0 a2 00 00 00 92 8b 03 8b 00 25 ff ff 00 00 50 8b 06 50 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 fc 0f b6 74 18 ff 8b c6 83 c0 df 83 e8 5e 73 1e 8b 45 f8 e8 ?? ?? ?? ?? 8d 44 18 ff 50 8d 46 0e b9 5e 00 00 00 99 f7 f9 83 c2 21 58 88 10 43 4f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_ARE_2147900189_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.ARE!MTB"
        threat_id = "2147900189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 b5 f8 fb ff ff 89 b5 e8 fb ff ff 89 b5 d8 fb ff ff 89 b5 c8 fb ff ff 89 b5 b8 fb ff ff 89 b5 a8 fb ff ff 89 b5 98 fb ff ff 89 b5 88 fb ff ff 56 89 b5 78 fb ff ff 89 b5 68 fb ff ff 89 b5 58 fb ff ff 89 b5 48 fb ff ff 89 b5 38 fb ff ff 89 b5 28 fb ff ff 89 b5 18 fb ff ff 89 b5 08 fb ff ff 89 b5 f8 fa ff ff 89 b5 e8 fa ff ff 89 b5 d8 fa ff ff 89 b5 c8 fa ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_NA_2147902263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.NA!MTB"
        threat_id = "2147902263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {40 41 46 43 83 c4 04 5e 56 81 f6 ?? ?? ?? ?? 5e 53 57 83 c4}  //weight: 10, accuracy: Low
        $x_5_2 = "jenkins-workspace\\workspace\\client-builder-product\\Build\\Win32\\Release\\utorrent.pdb" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_CCHT_2147903461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.CCHT!MTB"
        threat_id = "2147903461"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 ca 8a 8c 0d ?? ?? ff ff 30 0e e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_ACR_2147912692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.ACR!MTB"
        threat_id = "2147912692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bb d3 46 1a 08 c1 e8 05 b8 98 ff a6 08 81 f3 77 78 21 23 81 ac 24 84 00 00 00 02 be 8c 45 81 f3 85 ee dc 7d 81 84 24 84 00 00 00 02 be 8c 45 8b 84 24 84 00 00 00 8a 8c 24 0b 01 00 00 08 8c 24 1c 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_ARR_2147913822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.ARR!MTB"
        threat_id = "2147913822"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3f 4d 42 4d 32 83 c4 04 81 cb ab 36 01 00 5b}  //weight: 1, accuracy: High
        $x_1_2 = {57 81 f7 bc ba 00 00 81 cf 8c c8 00 00 81 e7 06 6f 01 00 5f 57 57 83 c4 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_RPY_2147913978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.RPY!MTB"
        threat_id = "2147913978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXECUTE ( \"FileR\" & \"ead(FileOpen(EnvGet(\"\"T\"\" & \"\"E\"\" & \"\"M\"\" & \"\"P\"\")" wide //weight: 1
        $x_1_2 = "EXECUTE ( \"Dll\" & \"Call(H30mg(\"\"HFQMF\"\" &" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_AER_2147914227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.AER!MTB"
        threat_id = "2147914227"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 56 83 c4 04 81 c7 1a 66 01 00 5f c6 85 2c f6 ff ff 56 c6 85 2d f6 ff ff 69 c6 85 2e f6 ff ff 72 c6 85 2f f6 ff ff 74 c6 85 30 f6 ff ff 75 c6 85 31 f6 ff ff 61 c6 85 32 f6 ff ff 6c c6 85 33 f6 ff ff 50 c6 85 34 f6 ff ff 72 c6 85 35 f6 ff ff 6f c6 85 36 f6 ff ff 74 c6 85 37 f6 ff ff 65 c6 85 38 f6 ff ff 63 c6 85 39 f6 ff ff 74 c6 85 3a f6 ff ff 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_NE_2147915613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.NE!MTB"
        threat_id = "2147915613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 40 00 74 00 65 00 6d 00 70 00 64 00 69 00 72 00 22 00 20 00 29 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 45 58 45 43 55 54 45 20 28 20 22 40 74 65 6d 70 64 69 72 22 20 29 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_2_3 = "= FILEREAD ( FILEOPEN ( EXECUTE ( \"@tempdir\" ) &" ascii //weight: 2
        $x_2_4 = "= ASC ( STRINGMID (" ascii //weight: 2
        $x_2_5 = "= BITXOR (" ascii //weight: 2
        $x_2_6 = "&= CHR (" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Remcos_AOS_2147916021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.AOS!MTB"
        threat_id = "2147916021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {84 e5 30 4a 04 03 ee 0a 40 4e 4d 35 43 38 3a 5d bd 05 03 03 03 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_KAAW_2147916130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.KAAW!MTB"
        threat_id = "2147916130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dobbelteksponeringer\\Microsoft\\Windows\\horizontical\\Uninstall\\spalteteksternes" ascii //weight: 1
        $x_1_2 = "vandrerkortet\\Angrebstidspunktet\\indonesiens" ascii //weight: 1
        $x_1_3 = "unsped\\akkorderingernes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_NH_2147916732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.NH!MTB"
        threat_id = "2147916732"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 40 00 54 00 65 00 6d 00 70 00 44 00 69 00 72 00 22 00 20 00 29 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 45 58 45 43 55 54 45 20 28 20 22 40 54 65 6d 70 44 69 72 22 20 29 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 4, accuracy: Low
        $x_2_3 = "= EXECUTE ( \"FileRead(FileOpen(@TempDir  &" ascii //weight: 2
        $x_2_4 = "= EXECUTE ( \"StringStripWS(" ascii //weight: 2
        $x_2_5 = "= EXECUTE ( \"Asc(StringMid" ascii //weight: 2
        $x_2_6 = "= EXECUTE ( \"BitXOR(" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Remcos_AREM_2147918614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.AREM!MTB"
        threat_id = "2147918614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 7c d6 83 58 35 33 34 55 bf 64 d2 8c 02 ?? ?? ?? ?? bf 45 d5 8f 07 37 35 37 56 b8 7b df 8e ?? ?? ?? ?? 50 b8 65 dc 89 51 32 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_AMR_2147924103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.AMR!MTB"
        threat_id = "2147924103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 10 ff 0f b6 c0 33 d2 05 ?? ?? ?? ?? 83 d2 00 8b d0 8d 85 [0-4] e8 ?? ?? ?? ?? 8b 95 01 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 05 ?? ?? ?? ?? 4e 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_NR_2147928598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.NR!MTB"
        threat_id = "2147928598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {46 4d 41 39 33 3f 83 c4 04 58 50 53 83 c4 04 81 e8 bf ee 00 00 58 69 8d}  //weight: 3, accuracy: High
        $x_2_2 = {3a 48 3c 5e 50 51 83 c4 04 e8 0b 00 00 00 00 33 3c 3d 50}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_NR_2147928598_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.NR!MTB"
        threat_id = "2147928598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2b d0 83 f2 00 0f af 95 ?? ?? ff ff 69 8d ?? ?? ff ff f1 fe c9 98 2b d1 89 95 ?? ?? ff ff e9 ?? ?? ?? ?? c7 85 ?? ?? ff ff 01 00 00 00}  //weight: 3, accuracy: Low
        $x_2_2 = {2b d0 33 95 ?? ?? ff ff 0f af 95 ?? ?? ff ff 69 8d ?? ?? ff ff f1 fe c9 98}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_LMV_2147931025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.LMV!MTB"
        threat_id = "2147931025"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 83 c4 04 81 eb 9f 9c 00 00 5b 8b 8d ?? ?? ff ff 0f b6 94 0d ?? ?? ff ff 8b 85 ?? ?? ff ff 03 85 ?? ?? ff ff 0f b6 08 33 ca 8b 95 60 f0 ff ff 03 95 d0 fa ff ff 88 0a e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_GPPB_2147931801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.GPPB!MTB"
        threat_id = "2147931801"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 1f 00 81 f3 ?? ?? ?? ?? 0f 1f 00 0f 1f 00 0f 1f 00 0f 72 f0 ?? 0f 1f 00 0f 1f 00 0f 1f 00 0f 1f 00 0f 1f 00 0f 1f 00 0f 6f c8 0f 1f 00 0f 1f 00 0f 1f 00 0f 1f 00 0f 1f 00 0f 1f 00 66 0f e8 f6 0f 1f 00 0f 1f 00 0f 1f 00 89 1c 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_BSA_2147932044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.BSA!MTB"
        threat_id = "2147932044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {00 86 93 0f 66 f9 09 0f 66 ba 02 0f 66 41 09 0f 66 74 a2 0d 66 6e 02 0f 66 06 03 0f 66 06 04 0f}  //weight: 4, accuracy: High
        $x_4_2 = {44 96 0f 66 11 dd 0e 66 00 00 00 00 00 00 00 00 01 00 08 00 96 59 40 00}  //weight: 4, accuracy: High
        $x_4_3 = {66 ee 94 0f 66 ea 62 0f 66 74 9b 0c 66 f6 09 0f 66 87 9b 0c 66 93 95 0f 66 85 9a 0c 66 df 47 0e}  //weight: 4, accuracy: High
        $x_4_4 = {66 89 06 0f 66 ba 03 0f 66 13 75 10 66 2b 94 0f 66 37 a2 0d 66 3a 03 0f 66 3a 04 0f 66 6e 03 0f}  //weight: 4, accuracy: High
        $x_2_5 = {ff ff ff c1 ff ff fc 3c 7f ff c3 fc 1f f8 3f fc 07 fb ff fc 1f fb ff fc 7f fb ff fd ff fb ff fd}  //weight: 2, accuracy: High
        $x_2_6 = {ff fb ff fd ff fb ff fd ff fb ff fd ff fb ff fd ff fb ff fd ff fb ff fd ff fb ff c1 ff fb fc 3d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_ACS_2147934262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.ACS!MTB"
        threat_id = "2147934262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 7b 0c 8b cd e8 76 ?? ?? ?? 8b cb 8b f0 e8 6d ?? ?? ?? 33 f0 23 74 24 10 31 34 97 42 8b 33 3b d6 7c dd}  //weight: 3, accuracy: Low
        $x_2_2 = {c1 ee 03 6a 13 5a 8b cb 33 fe e8 d6 ?? ?? ?? 6a 11 5a 8b cb 8b f0 e8 ca ?? ?? ?? 33 f0 c1 eb 0a 33 f3 8d 6d 04 03 fe 03 7d c4 03 7d e8 83 6c 24 28 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_CAA_2147935607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.CAA!MTB"
        threat_id = "2147935607"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {31 db 53 53 53 54 6a 00 c7 04 24 00 20 04 00 52 51 54}  //weight: 4, accuracy: High
        $x_4_2 = {83 ec 1c d9 e4 d9 34 24 8b 74 24 0c 83 c6 10 83 c4 1c c3}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_AROS_2147938481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.AROS!MTB"
        threat_id = "2147938481"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {59 33 f6 8b f8 56 56 56 6a 01 56 ff 15 ?? ?? ?? ?? 56 68 00 00 00 80 56 56 8b e8 68 b4 d9 46 00 55}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_HB_2147942493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.HB!MTB"
        threat_id = "2147942493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 20 00 2f 00 73 00 74 00 65 00 78 00 74 00 20 00 63 00 3a 00 5c 00 75 00 73 00 65 00 72 00 73 00 5c 00 [0-96] 5c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 6c 00 6f 00 63 00 61 00 6c 00 5c 00 74 00 65 00 6d 00 70 00 5c 00}  //weight: 1, accuracy: Low
        $n_100_2 = {2f 00 73 00 74 00 65 00 78 00 74 00 20 00 63 00 3a 00 5c 00 75 00 73 00 65 00 72 00 73 00 5c 00 [0-96] 5c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 6c 00 6f 00 63 00 61 00 6c 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 [0-96] 2e 00}  //weight: -100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_GVC_2147946059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.GVC!MTB"
        threat_id = "2147946059"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {30 84 0a 17 00 00 00 02 84 0a 17 00 00 00 e2 f0}  //weight: 3, accuracy: High
        $x_3_2 = {30 94 0e 17 00 00 00 02 94 0e 17 00 00 00 e2 f0}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Remcos_ARMS_2147948105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.ARMS!MTB"
        threat_id = "2147948105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {83 c4 18 8d 45 f0 50 8d 45 a8 50 57 57 68 00 00 00 08 57 57 57 68 58 89 46 00 68 dc 89 46 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_ARSM_2147948269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.ARSM!MTB"
        threat_id = "2147948269"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 30 f1 46 00 68 f0 ea 46 00 ff d7 50 ff d6 68 48 f1 46 00 bd 94 ee 46 00 a3 30 7b 47 00 55 ff d7 50 ff d6 68 60 f1 46 00 55 a3 1c 7b 47 00 ff d3 50 ff d6 68 70 f1 46 00 55 a3 28 7b 47 00 ff d3 50 ff d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_ABK_2147948771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.ABK!MTB"
        threat_id = "2147948771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 84 15 ?? ?? ?? ?? 8b 8d ec ee ff ff 03 8d 68 fa ff ff 0f b6 11 33 d0 8b 85 ec ee ff ff 03 85 68 fa ff ff 88 10 e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_NJ_2147948817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.NJ!MTB"
        threat_id = "2147948817"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {eb 0f 8b 8d 58 fc ff ff 83 c1 01 89 8d 58 fc ff ff 8b 95 5c fc ff ff 8b 85 58 fc ff ff 3b 42 18 0f 83 f9}  //weight: 2, accuracy: High
        $x_1_2 = {f0 eb ff ff 8b 85 e0 fd ff ff 03 04 8a 89 85 54 fc ff}  //weight: 1, accuracy: High
        $x_1_3 = "32\\A.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Remcos_AF_2147951438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remcos.AF!MTB"
        threat_id = "2147951438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {82 9b 6f 0b 9f 43 5e 08 67 34 35 3e 01 ?? 33 36 89 29 92 58 ae 15 21 c7 ac 74 87 b5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

