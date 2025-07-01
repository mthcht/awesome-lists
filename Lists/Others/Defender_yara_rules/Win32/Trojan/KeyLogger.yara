rule Trojan_Win32_KeyLogger_J_2147726022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KeyLogger.J!bit"
        threat_id = "2147726022"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "software\\microsoft\\windows\\currentversion\\run" ascii //weight: 1
        $x_1_2 = {0f b6 54 32 ff 66 33 d3 0f b7 d2 2b d6 33 d6 2b d6 33 d6 88 54 30 ff 43 8b 45 ?? e8 ?? ?? ?? ?? 0f b7 f3 3b c6 7f}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 74 31 fc 8d 7c 39 fc c1 f9 02 78 11 fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KeyLogger_G_2147763532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KeyLogger.G!MSR"
        threat_id = "2147763532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\WINDOWS\\SYSTEM32\\H@tKeysH@@k.DLL" ascii //weight: 1
        $x_1_2 = "HotKeysHookClass" ascii //weight: 1
        $x_1_3 = "HotKeysHook System-Wide Message Hook DLL" ascii //weight: 1
        $x_1_4 = "ClientGetKeyProc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KeyLogger_PAA_2147773919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KeyLogger.PAA!MTB"
        threat_id = "2147773919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "430"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "InternetConnectA" ascii //weight: 30
        $x_30_2 = "InternetOpenUrlA" ascii //weight: 30
        $x_30_3 = "GetAsyncKeyState" ascii //weight: 30
        $x_30_4 = "GetWindowTextA" ascii //weight: 30
        $x_30_5 = "InternetOpenA" ascii //weight: 30
        $x_30_6 = "computername" wide //weight: 30
        $x_30_7 = "keybd_event" ascii //weight: 30
        $x_30_8 = "/upload.php" wide //weight: 30
        $x_30_9 = "/copy.php" wide //weight: 30
        $x_30_10 = "PostFile" ascii //weight: 30
        $x_30_11 = "t_save" ascii //weight: 30
        $x_30_12 = "t_grab" ascii //weight: 30
        $x_30_13 = "t_cmd" ascii //weight: 30
        $x_30_14 = "t_key" ascii //weight: 30
        $x_1_15 = "[ PageDown ]" wide //weight: 1
        $x_1_16 = "[ WINDOWS ]" wide //weight: 1
        $x_1_17 = "[ SELECT ]" wide //weight: 1
        $x_1_18 = "[ PageUp ]" wide //weight: 1
        $x_1_19 = "[ PAUSE ]" wide //weight: 1
        $x_1_20 = "[ PRINT ]" wide //weight: 1
        $x_1_21 = "[ RIGHT ]" wide //weight: 1
        $x_1_22 = "[ CAPS ]" wide //weight: 1
        $x_1_23 = "[ CTRL ]" wide //weight: 1
        $x_1_24 = "[ CANC ]" wide //weight: 1
        $x_1_25 = "[ HOME ]" wide //weight: 1
        $x_1_26 = "[ LEFT ]" wide //weight: 1
        $x_1_27 = "[ DOWN ]" wide //weight: 1
        $x_1_28 = "[ HELP ]" wide //weight: 1
        $x_1_29 = "[ TAB ]" wide //weight: 1
        $x_1_30 = "[ ALT ]" wide //weight: 1
        $x_1_31 = "[ ESC ]" wide //weight: 1
        $x_1_32 = "[ END ]" wide //weight: 1
        $x_1_33 = "[ INS ]" wide //weight: 1
        $x_1_34 = "[ DEL ]" wide //weight: 1
        $x_1_35 = "[ UP ]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((14 of ($x_30_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_KeyLogger_Spyrix_2147787872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KeyLogger.Spyrix.AMH!MTB"
        threat_id = "2147787872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "AMH: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Keylogger" ascii //weight: 3
        $x_3_2 = "Spyrix" ascii //weight: 3
        $x_3_3 = "Software\\ASProtect\\SpecData" ascii //weight: 3
        $x_3_4 = "GhlfQfwkpwecF" ascii //weight: 3
        $x_3_5 = "\\System\\Iosubsys\\Smartvsd.vxd" ascii //weight: 3
        $x_3_6 = "blacklisted key" ascii //weight: 3
        $x_3_7 = "LastKey" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KeyLogger_RFS_2147793760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KeyLogger.RFS!MTB"
        threat_id = "2147793760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "temp{%lu}.tmp" ascii //weight: 1
        $x_1_2 = "temp{DE3B8DE236BD}.tmp" ascii //weight: 1
        $x_1_3 = "temp%d.zip" ascii //weight: 1
        $x_1_4 = "Codes\\MAIO\\MAIO\\MAIO-v3\\Release\\MAIO.pdb" ascii //weight: 1
        $x_1_5 = "[CtrlR]" ascii //weight: 1
        $x_1_6 = "[WinR]" ascii //weight: 1
        $x_1_7 = "[VolD]" ascii //weight: 1
        $x_1_8 = "[Exec]" ascii //weight: 1
        $x_1_9 = "[Esc]" ascii //weight: 1
        $x_1_10 = "[NumLock]" ascii //weight: 1
        $x_1_11 = "[ArrowL]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KeyLogger_SV_2147818993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KeyLogger.SV!MTB"
        threat_id = "2147818993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\AD:\\KEY\\TESTO\\configuration.vbp" wide //weight: 1
        $x_1_2 = "http://r3dir.com/2pdate.php" wide //weight: 1
        $x_1_3 = "APOSTROFE" wide //weight: 1
        $x_1_4 = "<hr>[_C.o.p.y_]<p>" wide //weight: 1
        $x_1_5 = "<p>[_P.a.s.t.e_]<hr>" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KeyLogger_BE_2147836470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KeyLogger.BE!MTB"
        threat_id = "2147836470"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 0c 73 15 8b 55 08 03 55 fc 8a 02 32 45 10 8b 4d 08 03 4d fc 88 01 eb}  //weight: 2, accuracy: High
        $x_2_2 = {6a 04 68 00 10 00 00 8b 55 f4 52 6a 00 ff 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KeyLogger_BE_2147836470_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KeyLogger.BE!MTB"
        threat_id = "2147836470"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {10 8a 85 55 28 2a 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 21 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 43 6c 61 73}  //weight: 2, accuracy: High
        $x_2_2 = {05 4f 9a c3 ec bd 05 f0 3e 8e 3a 4f ad 33 99 66 cf 11 b7 0c 00 aa 00 60 d3 93 46 6f 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KeyLogger_BF_2147836584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KeyLogger.BF!MTB"
        threat_id = "2147836584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {34 e5 48 88 64 1d be 5a a9 ac af a6 4a be dc 59 e7 53 49 ad 35 70 8c 82 bc 3d 18 0b 96 b5 9b a2 72 ea 49 ad 78}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KeyLogger_BF_2147836584_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KeyLogger.BF!MTB"
        threat_id = "2147836584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 31 00 fa 4e ad 33 99 66 cf 11 b7 0c 00 aa 00 60 d3 93 76}  //weight: 2, accuracy: High
        $x_2_2 = {66 97 57 4b 89 74 09 a7 d3 2d ef 05 c1 40 44 13 01 14 a7 d4 63 b5 1a 5f cc 7a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KeyLogger_BG_2147837295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KeyLogger.BG!MTB"
        threat_id = "2147837295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b 33 71 b5 97 6f 33 3f 65 59 e5 4a bd 35 bf c9 a8 1c ad 89 2a 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 5b d1 b8 19 3c 0a ef 4b}  //weight: 1, accuracy: High
        $x_1_2 = {fe 11 7a 90 a5 08 12 4b ab 76 e5 f0 4d b4 80 30 06 a8 d6 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KeyLogger_BG_2147837295_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KeyLogger.BG!MTB"
        threat_id = "2147837295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {1b 14 6f 38 7a ad ad 00 00 ad 32 67 a2 80 22 6f 58 4b 40 54 54 35 17 17 54 54 17 17 35 35 35 35 35 b0 b0 35 35 17 54 40 3f 2a 2a 58 7f}  //weight: 2, accuracy: High
        $x_1_2 = "Log Submitted!" wide //weight: 1
        $x_1_3 = "c.exe -o" wide //weight: 1
        $x_1_4 = "[[PASTE]]" wide //weight: 1
        $x_1_5 = "C L R  The Log ?" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KeyLogger_BH_2147838503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KeyLogger.BH!MTB"
        threat_id = "2147838503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 00 5d fb 33 1c 56 08 00 22 f5 01 00 00 00 6c 00 fe 9e 05 06 00 24 07 00 0f 28 03 19 7c fe 08 7c fe 0d a4 00 2f 00 1a 7c fe 00 02 00 0b 04 ec fd fe 7e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KeyLogger_BAB_2147840024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KeyLogger.BAB!MTB"
        threat_id = "2147840024"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "141.147.43.219:3000/ftp/EmmetPROD.exe" wide //weight: 2
        $x_1_2 = "C:\\Program Files\\Microsoft\\OneDrive\\EdgeUpdater.exe" ascii //weight: 1
        $x_1_3 = "destruct.bat" ascii //weight: 1
        $x_1_4 = "z.exe" ascii //weight: 1
        $x_1_5 = "[Print Screen]" ascii //weight: 1
        $x_1_6 = "[Scroll Lock]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KeyLogger_ASH_2147896695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KeyLogger.ASH!MTB"
        threat_id = "2147896695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%08x.exe" ascii //weight: 2
        $x_2_2 = "3301Kira" ascii //weight: 2
        $x_1_3 = "DC_MUTEX-4WTL4ZR" ascii //weight: 1
        $x_1_4 = "GBvoNidDMOgIUGJ1uvZQ3pebCSjCwLBcHXV3CxaptDcVDhL8Swmsad0fkKexT5ewRfaQ2dw5Ro4cOLWcZrCaG" ascii //weight: 1
        $x_1_5 = "Keylogger is up and running" ascii //weight: 1
        $x_1_6 = "155.15.133.69" ascii //weight: 1
        $x_1_7 = "197.182.186.212" ascii //weight: 1
        $x_1_8 = "schtasks /create /tn \"MyTask\" /tr \"%s\" /sc daily /st 12:00" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_KeyLogger_ASI_2147896906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KeyLogger.ASI!MTB"
        threat_id = "2147896906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "3301Kira" ascii //weight: 1
        $x_1_2 = "Software\\def9b6cd3f2b0c43097dfbc918862b82" wide //weight: 1
        $x_1_3 = "DC_MUTEX-4WTL4ZR" ascii //weight: 1
        $x_1_4 = "Keylogger is up and running" ascii //weight: 1
        $x_1_5 = {44 4e 5d 00 5b 45 4e 44 5d 00 00 00 5b 48 4f 4d 45 5d 00 00 5b 4c 45 46 54 5d 00 00 5b 52 49 47 48 54 5d 00 5b 44 4f 57 4e 5d 00 00 5b 50 52 49 4e 54 5d 00 5b 50 52 54 20 53 43 5d 00 00 00 00 5b 49 4e 53 45 52 54 5d 00 00 00 00 5b 44 45 4c 45 54 45 5d 00 00 00 00 5b 57 49 4e 20 4b 45 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_KeyLogger_ASI_2147896906_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KeyLogger.ASI!MTB"
        threat_id = "2147896906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "killerman" ascii //weight: 1
        $x_1_2 = "vbnbnbv,bnnbnvvn,tyrggg,qwwwweeee,iouyutr" wide //weight: 1
        $x_1_3 = "fk.exe" wide //weight: 1
        $x_1_4 = "]nwoDegaP[" wide //weight: 1
        $x_1_5 = "]emoH[" wide //weight: 1
        $x_1_6 = "[ ALTDOWN ]" wide //weight: 1
        $x_1_7 = "a9ew64jszjh70gt909c0ji9ln2bm1um27i00a3hepj144emtht" wide //weight: 1
        $x_1_8 = "c.exe -o " wide //weight: 1
        $x_1_9 = "werewrwwwwww" wide //weight: 1
        $x_1_10 = "S  u  r  e" wide //weight: 1
        $x_1_11 = "Are  You   Sure   You   Want To  Re-set Timer???" wide //weight: 1
        $x_1_12 = "Log Submitted!" wide //weight: 1
        $x_1_13 = "log.txt" wide //weight: 1
        $x_1_14 = "achibat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KeyLogger_PABZ_2147897093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KeyLogger.PABZ!MTB"
        threat_id = "2147897093"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bot started" ascii //weight: 1
        $x_1_2 = "Virus" ascii //weight: 1
        $x_1_3 = "#spam" ascii //weight: 1
        $x_1_4 = "KOSOMAKY4D" ascii //weight: 1
        $x_1_5 = "VrX- Bot ID: %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KeyLogger_AKI_2147898768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KeyLogger.AKI!MTB"
        threat_id = "2147898768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "3301Kira" ascii //weight: 1
        $x_1_2 = "Software\\def9b6cd3f2b0c43097dfbc918862b82" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KeyLogger_ASL_2147912340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KeyLogger.ASL!MTB"
        threat_id = "2147912340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {f7 d2 fe c8 f7 d1 ff 44 24 00 23 d1 f6 f0 66 f7 d0 89 14 26 f7 6c 24}  //weight: 5, accuracy: High
        $x_5_2 = {02 2b bc 53 20 c1 a9 24 66 80 75 66 7a 03 67 e2 cf 73 6b 58 9c c8 ce 9c a5 b2 d2 48 7c f3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KeyLogger_ASM_2147915755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KeyLogger.ASM!MTB"
        threat_id = "2147915755"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "-s -w -o s8ckxj3s.exe -X 'main.BinID=H' -X 'main.copy=True' -X 'main.domain=5i9.xyz" ascii //weight: 5
        $x_5_2 = "RLFo2ELugu-RnCpTGpwU/ygKEhI92tHWROKSSmhE9/oVvIRLjSr6olmGkivzY2/RLFo2ELugu-RnCpTGpwU" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KeyLogger_AMAD_2147919142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KeyLogger.AMAD!MTB"
        threat_id = "2147919142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "main.keyboardHook" ascii //weight: 2
        $x_2_2 = "main.keylogger" ascii //weight: 2
        $x_2_3 = "Starting keylogger" ascii //weight: 2
        $x_1_4 = "zaneGittins/go-inject/inject.init" ascii //weight: 1
        $x_1_5 = {6d 61 69 6e 2e 67 65 74 45 78 65 63 49 44 00 6d 61 74 68 2f 62 69 67 2e 28 2a 49 6e 74 29 2e 49 6e 74 36 34 00 6d 61 74 68 2f 62 69 67 2e 6c 6f 77 36 34 00 6d 61 69 6e 2e 66 69 6e 67 65 72 70 72 69 6e 74 43 50 55 00 6d 61 69 6e 2e 68 61 73 68 53 74 72 69 6e 67 00 68 61 73 68 2f 66 6e 76 2e 4e 65 77 33 32 61 00 6d 61 69 6e 2e 68 69 73 74 6f 72 79 54 6f 43 52 43}  //weight: 1, accuracy: High
        $x_1_6 = "(*tripleDESCipher).Decrypt" ascii //weight: 1
        $x_1_7 = {2d 00 6c 00 64 00 66 00 6c 00 61 00 67 00 73 00 3d 00 22 00 2d 00 73 00 20 00 2d 00 77 00 20 00 2d 00 6f 00 20 00 [0-30] 2e 00 65 00 78 00 65 00 20 00 2d 00 58 00 20 00 27 00 6d 00 61 00 69 00 6e 00 2e 00 42 00 69 00 6e 00 49 00 44 00 3d 00 ?? 27 00 20 00 2d 00 58 00 20 00 27 00 6d 00 61 00 69 00 6e 00 2e 00 63 00 6f 00 70 00 79 00 3d 00 [0-5] 27 00 20 00 2d 00 58 00 20 00 27 00 6d 00 61 00 69 00 6e 00 2e 00 64 00 6f 00 6d 00 61 00 69 00 6e 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_8 = {2d 6c 64 66 6c 61 67 73 3d 22 2d 73 20 2d 77 20 2d 6f 20 [0-30] 2e 65 78 65 20 2d 58 20 27 6d 61 69 6e 2e 42 69 6e 49 44 3d ?? 27 20 2d 58 20 27 6d 61 69 6e 2e 63 6f 70 79 3d [0-5] 27 20 2d 58 20 27 6d 61 69 6e 2e 64 6f 6d 61 69 6e 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_KeyLogger_NK_2147925900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KeyLogger.NK!MTB"
        threat_id = "2147925900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {33 c0 55 68 aa c1 49 00 64 ff 30 64 89 20 6a 00 8b 4d fc b2 01 a1 34 7c 41 00 e8 ?? ?? ?? ?? 8b d8 8b c3}  //weight: 3, accuracy: Low
        $x_1_2 = "zippassword=damagelab" ascii //weight: 1
        $x_1_3 = "ftp=xxxxxxxxxxxxxxx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KeyLogger_NL_2147931491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KeyLogger.NL!MTB"
        threat_id = "2147931491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "LazLogger" ascii //weight: 3
        $x_2_2 = "KeepConnectionTDY" ascii //weight: 2
        $x_1_3 = "DES_ecb_encrypt" ascii //weight: 1
        $x_1_4 = "fpopenssl.serrfailedtocreatessl" ascii //weight: 1
        $x_1_5 = "\\grb.dan" ascii //weight: 1
        $x_1_6 = "obeapp.exe" ascii //weight: 1
        $x_1_7 = "Press Abort to kill the program." ascii //weight: 1
        $x_1_8 = "KABx64" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KeyLogger_EJQQ_2147945211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KeyLogger.EJQQ!MTB"
        threat_id = "2147945211"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c1 8b 55 08 03 55 fc 88 02 ?? ?? b0 01 8b e5 5d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

