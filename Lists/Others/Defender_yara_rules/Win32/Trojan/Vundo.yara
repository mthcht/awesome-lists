rule Trojan_Win32_Vundo_D_93619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.D"
        threat_id = "93619"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CallNextHookEx" ascii //weight: 1
        $x_1_2 = "CreateRemoteThread" ascii //weight: 1
        $x_1_3 = "GetSystemDirectoryA" ascii //weight: 1
        $x_1_4 = "InternetReadFile" ascii //weight: 1
        $x_1_5 = "OpenProcess" ascii //weight: 1
        $x_1_6 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_7 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_8 = "ShellExecuteA" ascii //weight: 1
        $x_1_9 = "TerminateProcess" ascii //weight: 1
        $x_1_10 = "WriteProcessMemory" ascii //weight: 1
        $x_1_11 = "amaena.com" ascii //weight: 1
        $x_1_12 = "antivirussecuritypro.com" ascii //weight: 1
        $x_1_13 = "drivecleaner.com" ascii //weight: 1
        $x_1_14 = "errorprotector.com" ascii //weight: 1
        $x_1_15 = "errorsafe.com" ascii //weight: 1
        $x_1_16 = "stopguard.com" ascii //weight: 1
        $x_1_17 = "sysprotect.com" ascii //weight: 1
        $x_1_18 = "systemdoctor.com" ascii //weight: 1
        $x_1_19 = "virusguard.com" ascii //weight: 1
        $x_1_20 = "winantispy.com" ascii //weight: 1
        $x_1_21 = "winantispyware" ascii //weight: 1
        $x_1_22 = "winantispyware.com" ascii //weight: 1
        $x_1_23 = "winantivirus.com" ascii //weight: 1
        $x_1_24 = "winantiviruspro.com" ascii //weight: 1
        $x_1_25 = "windrivecleaner.com" ascii //weight: 1
        $x_1_26 = "winfirewall.com" ascii //weight: 1
        $x_1_27 = "winfixer.com" ascii //weight: 1
        $x_1_28 = "winpopupguard.com" ascii //weight: 1
        $x_1_29 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_30 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify" ascii //weight: 1
        $x_1_31 = {43 72 65 61 74 65 4d 61 69 6e 50 72 6f 63 00 43 72 65 61 74 65 50 72 6f 74 65 63 74 50 72 6f 63}  //weight: 1, accuracy: High
        $x_1_32 = {52 65 61 6c 4c 6f 67 6f 66 66 00 52 65 61 6c 4c 6f 67 6f 6e}  //weight: 1, accuracy: High
        $x_1_33 = {61 77 78 5f 6d 75 74 61 6e 74 00 00 61 64 2d 61 77 61 72 65 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_34 = {73 73 77 5f 6d 75 74 61 6e 74 00 00 77 72 73 73 73 64 6b 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_35 = {68 6a 74 5f 6d 75 74 61 6e 74 00 00 68 69 6a 61 63 6b 74 68 69 73 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_36 = "#'yu[QV9w!>-6G.4tg`xnkdE$~Arf&I?_|qm\\NCST:/bKaH2Z=c" ascii //weight: 1
        $x_1_37 = "+6Zrp*S2u)v_l/e1R%z@L(s[WVnOax'FPEAIQ}HT?fU]BmY~M0dbt3" ascii //weight: 1
        $x_1_38 = "yPo0q-uz(JXiR+@l;eG\\8x.O?UM|dFgr&~HI`'VshQ%EZYA3NLS7W=2paw6{D5^]C<}1$_)4#jbBv:T" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (30 of ($x*))
}

rule Trojan_Win32_Vundo_100135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo"
        threat_id = "100135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 40 42 0f 00 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {68 00 14 01 00 68 c8 43 40 00 50}  //weight: 1, accuracy: High
        $x_1_3 = {c1 ea 0b 83 e2 03 8b c3 c1 e8 05 8b cb c1 e1 04 33 c1 8b 4c 95 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Vundo_V_116700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.V"
        threat_id = "116700"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "&v=%x_%x_%x_%x_%s" ascii //weight: 5
        $x_5_2 = "&avs=%i" ascii //weight: 5
        $x_1_3 = "Explorer\\ShellExecuteHooks" ascii //weight: 1
        $x_1_4 = "explorer.exe" ascii //weight: 1
        $x_1_5 = "AntiVirus" ascii //weight: 1
        $x_3_6 = "Norton " ascii //weight: 3
        $x_3_7 = "BitDefender" ascii //weight: 3
        $x_3_8 = "avast!" ascii //weight: 3
        $x_5_9 = "SeDebugPrivilege" ascii //weight: 5
        $x_5_10 = "PrivacySetZonePreference" ascii //weight: 5
        $x_5_11 = "RtlTimeToSecondsSince1970" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_1_*))) or
            ((5 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((5 of ($x_5_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_C_118995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!C"
        threat_id = "118995"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 04 85 c0 74 27 8a 08 80 f9 ff 75 0d 80 78 01 25 75 07 8b 40 02 8b 00 eb 13 80 f9 e9 75 0e 83 7c 24 08 00 74 07 8b 48 01 8d 44 08 05}  //weight: 1, accuracy: High
        $x_1_2 = {80 c2 61 83 65 08 00 88 11 33 d2 6a 05 5b 8b c7 f7 f3 8d 71 01 0f be 09 6a 19 0f be c2 03 c1 99 59 f7 f9 6a 0a 8b ce 8b c7 80 c2 61 88 16 33 d2 5e f7 f6 ff 45 08 39 5d 08 8b f8 7c cc}  //weight: 1, accuracy: High
        $x_1_3 = {80 c2 61 29 75 08 88 16 8b c1 83 e0 01 6a 05 40 33 d2 5b 83 f8 01 8d 7e 01 6a 19 8b c1 75 13 f7 f3}  //weight: 1, accuracy: High
        $x_1_4 = {6a 02 57 8b f0 6a f3 56 ff 15 ?? ?? ?? ?? 57 8d 44 24 ?? 50 6a 0d 68}  //weight: 1, accuracy: Low
        $x_1_5 = {eb 2f 6a 02 56 6a f3 53 c7 45 f8 0d 00 00 00 ff d7 56 8d 45 f8 50 ff 75 f8 8d 45 dc 50 53}  //weight: 1, accuracy: High
        $x_2_6 = {89 45 14 74 53 33 ff f7 06 fc ff ff ff 76 49 68 04 01 00 00 8d 85 fc fe ff ff 50 ff 34 bb ff 75 08 ff 15 ?? ?? ?? ?? 85 c0 74 23 8d 85 fc fe ff ff 50 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 85 fc fe ff ff 50 ff 15 ?? ?? ?? ?? 85 c0 75 14 8b 06}  //weight: 2, accuracy: Low
        $x_2_7 = {6a 0d ff 75 fc 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 75 15 ff b5 ?? ?? ff ff 53 6a 01 ff 15 ?? ?? ?? ?? 8b f8 3b fb 75 15 8d 85 ?? ?? ff ff 50 ff 75 f8 e8 ?? ?? ?? ?? 85 c0 75 9a eb 0b 53}  //weight: 2, accuracy: Low
        $x_1_8 = {2f 3f 63 6d 70 3d 76 6d 74 65 6b 5f [0-10] 26 6c 69 64 3d 72 75 6e 26 75 69 64 3d 25 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_E_119448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!E"
        threat_id = "119448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5d 10 8b 75 0c 59 33 c9 85 db 89 45 fc 76 12 33 d2 8b c1 f7 75 fc 8a 04 3a 30 04 31 41 3b cb 72 ee 5f c6 04 1e 00}  //weight: 1, accuracy: High
        $x_1_2 = {3b c6 59 76 6d 8d 85 ?? ?? ff ff 48 48 89 85 ?? ?? ff ff eb 06 8b 85 ?? ?? ff ff 8d 7e 01 80 3c 38 3b 75 3b 2b f3 56 8d}  //weight: 1, accuracy: Low
        $x_1_3 = {3b c6 59 76 74 8d 85 ?? ?? ff ff 48 48 89 85 ?? ?? ff ff eb 06 8b 85 ?? ?? ff ff 8d 5e 01 80 3c 18 3b 75 3b 2b f7 56 8d}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 4e 56 ff 15 ?? ?? ?? ?? 83 f8 ff 74 3a 53 8d 85 ?? ?? ff ff 50 6a 0d 8d 45 ec 50 56 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Vundo_BI_119853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.BI"
        threat_id = "119853"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 a4 27 92 7f aa 83 48 9c 51 18 06 83 fa 3e 74 0f 0a 75 3b 7a 0e 3b c1 2c 01 c8 75 ec 33 c0 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_CQ_121236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.CQ!dll"
        threat_id = "121236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "210"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "16B435F6-B6CE-4F24-A568-944B27ED919C" ascii //weight: 100
        $x_100_2 = "targettedbanner.biz" ascii //weight: 100
        $x_1_3 = "&tail=" wide //weight: 1
        $x_1_4 = "&exceed=" wide //weight: 1
        $x_1_5 = "&tm=" wide //weight: 1
        $x_1_6 = "&id=" wide //weight: 1
        $x_1_7 = "&version=" wide //weight: 1
        $x_1_8 = "&clicked=" wide //weight: 1
        $x_1_9 = "showed=" wide //weight: 1
        $x_1_10 = "IsRotatorPopup" wide //weight: 1
        $x_1_11 = "clicklimit" wide //weight: 1
        $x_1_12 = "refresh_time" wide //weight: 1
        $x_1_13 = "glob_click_limit" wide //weight: 1
        $x_1_14 = "max_impress" wide //weight: 1
        $x_1_15 = "PopupMgr" wide //weight: 1
        $x_1_16 = "Internet Explorer_Server" wide //weight: 1
        $x_1_17 = "Content-Type: application/x-www-form-urlencoded" wide //weight: 1
        $x_1_18 = "opera" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_121770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo"
        threat_id = "121770"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "52"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "%08x___12" ascii //weight: 10
        $x_10_2 = "PendingFileRenameOperation" ascii //weight: 10
        $x_10_3 = "<redirect><" ascii //weight: 10
        $x_10_4 = "ANTISPYWARE?GCASSERVALERT.EXE" ascii //weight: 10
        $x_10_5 = "PopupsShown=%i;MaxPopupPerDay" ascii //weight: 10
        $x_1_6 = "g_AffiliateID" ascii //weight: 1
        $x_1_7 = "Local\\SysUpd" ascii //weight: 1
        $x_1_8 = "A lot of crashes" ascii //weight: 1
        $x_1_9 = "src=\"http://stat.errclean" ascii //weight: 1
        $x_1_10 = "campaignselection" ascii //weight: 1
        $x_1_11 = "sysprotect.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_N_121841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.N"
        threat_id = "121841"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 0f 00 00 00 68 9c c8 9e da}  //weight: 1, accuracy: High
        $x_1_2 = {68 07 00 00 00 68 34 55 6c cc}  //weight: 1, accuracy: High
        $x_1_3 = {e8 00 00 00 00 68 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_U_121979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.U"
        threat_id = "121979"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5a be e0 26 52 36 d1 34 1e 0d 93 5f df fe cc ee 49 bd c2 b1 d7 6f 8d 09 a8 2e 08 71 37 5b 87 1a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_Y_121980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.Y"
        threat_id = "121980"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 93 30 86 20 c3 d9 38 dc 13 87 2f 99 52 6f d0 c5 ae 6f 38 3f bd d9 38 d4 45 8b 48 20 8c 57 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_AG_122143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.AG"
        threat_id = "122143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {84 b2 96 b1 b4 ba 1a 10 b6 9c 00 aa 00 34 1d 07 73 00 63 00 6c 00 6a 00 6e 00 76 00 63 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {6b 00 65 00 79 00 77 00 6f 00 72 00 64 00 73 00 00 00 00 00 61 16 0c d3 af cd d0 11 8a 3e 00 c0 4f c9 e2 6e}  //weight: 1, accuracy: High
        $x_2_3 = {59 6a 00 6a 04 8b f8 57 56 ff 15 ?? ?? 01 10 33 c0 85 ff 7e 08 fe 04 30 40 3b c7 7c f8}  //weight: 2, accuracy: Low
        $x_1_4 = "Creating popup %s" ascii //weight: 1
        $x_1_5 = "/go/?cmp=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_FA_122263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.FA"
        threat_id = "122263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 65 74 20 73 74 6f 70 20 77 69 6e 73 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {6e 65 74 20 73 74 6f 70 20 4f 63 48 65 61 6c 74 68 4d 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {50 53 53 6a 26 53 33 f6 ff 15 ?? ?? 00 10 68 ?? ?? 00 10 8d 45 ?? 50 ff 15 ?? ?? 00 10 8d 45 ?? 50 ff 15 ?? ?? 00 10 8b f8 3b fb 74 ?? 68 ?? ?? 00 10 57 ff 15 ?? ?? 00 10 3b c3 74 ?? 53 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_KE_122271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.KE"
        threat_id = "122271"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {58 55 8b ec 53 09 00 68 ?? ?? ?? ?? 90 90 90}  //weight: 10, accuracy: Low
        $x_10_2 = {c7 04 24 00 80 00 00}  //weight: 10, accuracy: High
        $x_10_3 = {64 8b 3d 30 00 00 00 eb ?? eb eb eb eb eb eb eb eb eb eb}  //weight: 10, accuracy: Low
        $x_1_4 = {c6 45 f7 72 [0-4] c6 45 f8 33 [0-4] c6 45 f9 32}  //weight: 1, accuracy: Low
        $x_1_5 = {c6 45 f8 33 [0-4] c6 45 f9 32 [0-4] c6 45 fa 2e}  //weight: 1, accuracy: Low
        $x_1_6 = {c6 45 f9 32 [0-4] c6 45 fa 2e [0-4] c6 45 fb 64}  //weight: 1, accuracy: Low
        $x_1_7 = {c6 45 fa 2e [0-4] c6 45 fb 64 [0-4] c6 45 fc 6c}  //weight: 1, accuracy: Low
        $x_1_8 = {c6 45 fb 64 [0-4] c6 45 fc 6c [0-4] c6 45 fd 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_FJ_122292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.FJ"
        threat_id = "122292"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 5e 8b c6 50 e8 ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_1_2 = "/go/?cmp=hstwtch" ascii //weight: 1
        $x_1_3 = "red_green_test" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_EL_122848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.EL"
        threat_id = "122848"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "garbage_garbage" ascii //weight: 1
        $x_1_2 = "[morphid]" ascii //weight: 1
        $x_1_3 = "IsUserAdmin" ascii //weight: 1
        $x_1_4 = "BannerModifier_" ascii //weight: 1
        $x_1_5 = "WatchWndClass" wide //weight: 1
        $x_1_6 = "Software\\Microsoft\\IProxyProvider" wide //weight: 1
        $x_1_7 = "Software\\Microsoft\\dslcnnct" wide //weight: 1
        $x_1_8 = "SOFTWARE\\Microsoft\\ProxyPlugins" wide //weight: 1
        $x_1_9 = "dsl_logger_mmf" wide //weight: 1
        $x_1_10 = "dsl_proxy_mutex" wide //weight: 1
        $x_1_11 = "\\pskt.ini" wide //weight: 1
        $x_1_12 = "HTTP/1.1" wide //weight: 1
        $x_1_13 = "firefox.exe" wide //weight: 1
        $x_1_14 = "opera.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_G_122988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!G"
        threat_id = "122988"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 f9 6a 04 2b c1 68 00 10 00 00 8d 70 01 56 6a 00 ff 15 ?? ?? ?? 10 8a 0f 84 c9 74 0e 66 0f be c9 66 41 66 89 08 40 40 47 75 ec 66 83 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = {74 07 3d 38 0c 00 00 75 1f b0 01 c3 3d 0a 1a 00 00 74 f6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Vundo_AR_123068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.AR"
        threat_id = "123068"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fe 00 7d 00 00 [0-8] 0f 82 ?? 00 00 00 40 [0-4] 81 fe 00 05 00 00 [0-8] 0f 82 03 00 00 00 40 [0-4] 81 fe 80 00 00 00 [0-4] 0f 83 ?? 00 00 00 40}  //weight: 1, accuracy: Low
        $x_1_2 = {48 85 c0 75 ?? 5a}  //weight: 1, accuracy: Low
        $x_1_3 = {64 a1 30 00 00 00 [0-8] 89 45 fc [0-16] 8b 45 fc 8b 40 0c [0-21] 8b 48 0c [0-80] 90 90 90 90 90 [0-8] 8b 09 [0-8] 90 39 41 18 [0-4] 0f 85 ?? ff ff ff [0-16] 8b 15 ?? ?? 00 10 03 d0 [0-4] 89 51 1c 90 00 [0-16] 01 05 ?? 00 10 90 00 [0-16] 90 c9 eb}  //weight: 1, accuracy: Low
        $x_1_4 = "ntdll.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_AT_123103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.AT"
        threat_id = "123103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 [0-8] 89 45 fc [0-32] 8b 45 fc [0-8] 8b 40 0c [0-64] 8b 09 [0-4] 39 41 18 [0-4] 0f 85 f1 ff ff ff [0-32] 89 51 1c [0-32] c9 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {81 fe 00 7d 00 00 [0-4] 0f 82 ?? 00 00 00 [0-8] 81 fe 00 05 00 00 [0-72] 0f 82 ?? 00 00 00 40 [0-4] 81 fe 80 00 00 00 [0-4] 0f 83 ?? 00 00 00 40 [0-2] 40}  //weight: 1, accuracy: Low
        $x_1_3 = "ntdll.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_I_123161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!I"
        threat_id = "123161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {80 78 02 11 30 00 [0-35] 80 2d ?? ?? 00 10 b8 [0-8] ff 35 ?? ?? 00 10}  //weight: 3, accuracy: Low
        $x_3_2 = {a0 00 00 00 85 02 00 8b ?? ?? ?? ?? ?? ?? (c0|db|c9|d2|f6|ff|ed) eb}  //weight: 3, accuracy: Low
        $x_4_3 = {ff 0f 00 00 02 00 81 (e1|e2|e3) [0-12] eb [0-8] 03 (08|10|18)}  //weight: 4, accuracy: Low
        $x_2_4 = {64 a1 30 00 00 00}  //weight: 2, accuracy: High
        $x_2_5 = {8d 45 fc eb 00}  //weight: 2, accuracy: High
        $x_2_6 = {68 00 10 00 00 [0-4] 05 00 02 00 00}  //weight: 2, accuracy: Low
        $x_2_7 = {0f b7 50 14 eb}  //weight: 2, accuracy: High
        $x_2_8 = {6e 74 64 6c 6c 2e 64 6c 6c 00 00 00 00}  //weight: 2, accuracy: High
        $x_1_9 = {48 85 c0 75 ?? 5a}  //weight: 1, accuracy: Low
        $x_1_10 = {81 e2 ff 0f 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {8b 44 24 04 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_J_123682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!J"
        threat_id = "123682"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 5e 6a 02 53 88 1f 6a d8 88 1e 8b 35 ?? ?? ?? ?? 50 ff d6 83 f8 ff 74 14 53 8d 45 fc 50 6a 14 57}  //weight: 1, accuracy: Low
        $x_1_2 = {74 2b 56 56 6a 4e 57 ff 15 ?? ?? ?? ?? 83 f8 ff 74 14 56 8d 45 0c 50 ff 75 10 53 57 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {83 f8 04 7e 25 8d 74 30 fc bf ?? ?? ?? ?? 57 56 ff 15 ?? ?? ?? ?? 85 c0 74 22 83 c3 05 83 c7 05 83 fb 0f 72 e9 8b 7d f0 33 db ff 45 f8 8b 45 f8 83 45 fc 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Vundo_AX_123759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.AX"
        threat_id = "123759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 c6 15 c8 75}  //weight: 1, accuracy: High
        $x_1_2 = {81 f1 28 76 58 2b}  //weight: 1, accuracy: High
        $x_1_3 = {b9 15 07 91 45}  //weight: 1, accuracy: High
        $x_1_4 = {81 f1 4f 68 4f ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_AY_123902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.AY"
        threat_id = "123902"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 49 6e 69 74 53 65 63 75 72 69 74 79 49 6e 74 65 72 66 61 63 65 57 00 4c 73 61 41 70 43 61 6c 6c 50 61 63 6b 61 67 65 00 4c 73 61 41 70 43 61 6c 6c 50 61 63 6b 61 67 65 50 61 73 73 74 68 72 6f 75 67 68 00 4c 73 61 41 70 43 61 6c 6c 50 61 63 6b 61 67 65 55 6e 74 72 75 73 74 65 64 00 4c 73 61 41 70 49 6e 69 74 69 61 6c 69 7a 65 50 61 63 6b 61 67 65 00 4c 73 61 41 70 4c 6f 67 6f 6e 54 65 72 6d 69 6e 61 74 65 64 00 4c 73 61 41 70 4c 6f 67 6f 6e 55 73 65 72 00 4c 73 61 41 70 4c 6f 67 6f 6e 55 73 65 72 45 78 00 53 70 49 6e 69 74 69 61 6c 69 7a 65 00 63 00 66 00 6f 00 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_BX_124436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.BX"
        threat_id = "124436"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "411"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "del %1" ascii //weight: 100
        $x_100_2 = "if exist %1 goto" ascii //weight: 100
        $x_100_3 = "rundll32.exe %s,a" ascii //weight: 100
        $x_100_4 = "C:\\TEMP\\removalfile.bat" ascii //weight: 100
        $x_10_5 = "http://65.243.103." ascii //weight: 10
        $x_10_6 = "http://69.31.80." ascii //weight: 10
        $x_10_7 = "http://82.98.235." ascii //weight: 10
        $x_1_8 = "{8FD83B0B-987F-4f3f-8FB4-01529687C7B6}" ascii //weight: 1
        $x_1_9 = "{873358BC-262B-4695-ABB7-C0074C149EA0}" ascii //weight: 1
        $x_1_10 = "Certificate installation completed" wide //weight: 1
        $x_1_11 = "Your e-mail account is no longer subject to termination" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((4 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_BY_124513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.BY"
        threat_id = "124513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fa 8f 80 bf b1 50 67 73 43 44 54 ca 6d af 50 c0 5f 49 6e 73 74 6d 61 c6 46 d9 68 4e 10 1c 44 4c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_L_124522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!L"
        threat_id = "124522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 e6 10 d2 70}  //weight: 2, accuracy: High
        $x_1_2 = {68 fe 6a 7a 69}  //weight: 1, accuracy: High
        $x_2_3 = {68 e1 1f f7 5a}  //weight: 2, accuracy: High
        $x_1_4 = {68 62 67 8d a4}  //weight: 1, accuracy: High
        $x_1_5 = "h_p5:" ascii //weight: 1
        $x_1_6 = {68 5a 6f de a9}  //weight: 1, accuracy: High
        $x_1_7 = {68 ee ea c0 1f}  //weight: 1, accuracy: High
        $x_1_8 = {68 bd 4d 54 7d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_M_124539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!M"
        threat_id = "124539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {aa 23 9c 41 03 00 (c7|?? ??)}  //weight: 2, accuracy: Low
        $x_1_2 = {8f 19 a5 13 03 00 (c7|?? ??)}  //weight: 1, accuracy: Low
        $x_1_3 = {94 c8 37 09 03 00 (c7|?? ??)}  //weight: 1, accuracy: Low
        $x_1_4 = {5a 45 79 74 03 00 (c7|?? ??)}  //weight: 1, accuracy: Low
        $x_1_5 = {3e cc eb 29 03 00 (c7|?? ??)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_HA_124710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.HA"
        threat_id = "124710"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bf 60 c4 ea 91}  //weight: 1, accuracy: High
        $x_1_2 = {81 ef 7a b3 18 21}  //weight: 1, accuracy: High
        $x_1_3 = {68 41 a6 ea a1}  //weight: 1, accuracy: High
        $x_1_4 = {b9 30 07 b4 d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_HB_124826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.HB"
        threat_id = "124826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 09 e4 cb fc}  //weight: 1, accuracy: High
        $x_1_2 = {bb dd 2c 06 74}  //weight: 1, accuracy: High
        $x_1_3 = {b9 95 97 56 2a}  //weight: 1, accuracy: High
        $x_1_4 = {81 f1 e4 36 08 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_HC_124827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.HC"
        threat_id = "124827"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 dc 42 24 83}  //weight: 1, accuracy: High
        $x_1_2 = {b9 f6 31 52 12}  //weight: 1, accuracy: High
        $x_1_3 = {bb 11 17 dc 33}  //weight: 1, accuracy: High
        $x_1_4 = {81 c3 60 8a 82 3e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_N_124967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!N"
        threat_id = "124967"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1a 9d d5 71 03 00 (c7|?? ??)}  //weight: 1, accuracy: Low
        $x_1_2 = {16 85 d9 5d 03 00 (c7|?? ??)}  //weight: 1, accuracy: Low
        $x_1_3 = {c0 41 6a 4e 03 00 (c7|?? ??)}  //weight: 1, accuracy: Low
        $x_1_4 = {b4 e4 39 28 03 00 (c7|?? ??)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_O_125094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!O"
        threat_id = "125094"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Windows NT\\CurrentVersion\\Winlogon\\Notify" ascii //weight: 1
        $x_1_2 = "CurrentVersion\\Explorer\\Browser Helper Objects\\" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Internet Account Manager\\Accounts\\" ascii //weight: 1
        $x_1_4 = {3c 72 65 64 69 72 65 63 74 3e 3c 00 6b 00 65 00 79 00 77 00 6f 00 72 00 64 00 73}  //weight: 1, accuracy: High
        $x_1_5 = {57 6f 72 6b 65 72 41 00 57 6f 72 6b 65 72 57}  //weight: 1, accuracy: High
        $x_1_6 = "g_PopupPerDay" ascii //weight: 1
        $x_1_7 = "g_ConnectionPerDay" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_HM_125126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.HM"
        threat_id = "125126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8d 47 20 dd 05 68 55 00 10 51 51 dd 1c 24 68 f0 75 00 10 51 8d 8d fc f7 ff ff 51 50 68 28 55 00 10 8d 85 fc ef ff ff 53 50 ff 15}  //weight: 3, accuracy: High
        $x_3_2 = {8d 43 20 dd 05 90 35 01 10 83 ec 08 dd 1c 24 68 e0 85 01 10 51 8d 8c 24 20 04 00 00 51 50 68 54 35 01 10 8d 94 24 2c 0c 00 00 68 00 04 00 00 52 e8}  //weight: 3, accuracy: High
        $x_3_3 = {73 0f 8a 88 ?? ?? ?? 10 30 88 ?? ?? ?? 10 40 eb ec 68 ?? ?? ?? 10 8d 4d d0 (e8|ff 15) ?? ?? ?? ?? 68 e0 93 04 00 ff 15 ?? ?? ?? 10 83 7d e8 10 8b 45 d4 73 03 8d 45 d4 57 57 56 8d 8d d0 fb ff ff 51 50 57 e8 1c 00 83 f8}  //weight: 3, accuracy: Low
        $x_1_4 = {25 73 3f 71 3d 25 73 26 75 3d 25 73 26 67 3d 25 73 26 76 3d 25 2e 32 66 26 6e 3d ?? ?? ?? 26 61 3d}  //weight: 1, accuracy: Low
        $x_1_5 = {31 32 37 2e 30 2e 30 2e 31 3a 34 36 36 34 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 63 6f 6d 72 75 73 2e 69 6e 66 00}  //weight: 1, accuracy: High
        $x_1_7 = {44 9d 00 3d 76 e6 73 43 b7 5f b0 3f 58 34 da f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_Q_125196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!Q"
        threat_id = "125196"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 7a 73 05 03 00 (c7|?? ??)}  //weight: 1, accuracy: Low
        $x_1_2 = {80 93 a5 5f 03 00 (c7|?? ??)}  //weight: 1, accuracy: Low
        $x_1_3 = {f4 57 cf 2b 03 00 (c7|?? ??)}  //weight: 1, accuracy: Low
        $x_1_4 = {92 f5 ee 39 03 00 (c7|?? ??)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_S_125493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!S"
        threat_id = "125493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d7 85 c0 0f 84 ?? 00 00 00 ff b5 ?? ?? ff ff 8d 45 ?? 50 68 ?? ?? ?? 10 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 45 fc 76 12 33 d2 8b c1 f7 75 fc 8a 04 3a 30 04 31}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 75 08 6a 48 50 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 45 14 8b 7c 85 f8 6a 22 83 ee 22 56 57 e8 ?? ff ff ff 83 c4 0c 4e 8a 06 4e 8a 0e 32 c1}  //weight: 1, accuracy: Low
        $x_1_3 = {eb 20 53 ff b5 ?? ?? ff ff ff 15 ?? ?? ?? 10 6a 0a 8d 4d d4 51 50 e8 ?? ?? 00 00 83 c4 0c}  //weight: 1, accuracy: Low
        $x_1_4 = {74 27 83 7d fc 10 75 21 8b 45 10 3b c3 8b 4d f8 74 02 89 08 38 5d 14 74 0e 8b 45 0c 6a 04 5a 31 08 83 c0 04 4a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Vundo_HT_125510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.HT"
        threat_id = "125510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 75 08 59 ff 75 fc 5a 8b 14 97 ?? ?? e8 ?? ?? ?? ?? 39 45 0c 0f 84 10 00 00 00 ff 45 fc ff 75 fc 58 3b 46 18 0f 82 d5 ff ff ff ff 75 fc 5a ff 75 08 59 ff 75 f4 58 3b 56 18 0f ?? ?? ?? ?? ?? 0f b7 04 50 8b 1c 83 ff 75 f8 58 ?? ?? ?? ?? 3b d8 89 5d 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 75 08 59 ff 75 fc 5a 8b 14 97 ?? ?? e8 ?? ?? ?? ?? 39 45 0c 0f 84 10 00 00 00 ff 45 fc ff 75 fc 58 3b 46 18 0f 82 d5 ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_IG_127116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.IG"
        threat_id = "127116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 61 00 66 00 68 00 6f 00 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_IJ_127252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.IJ"
        threat_id = "127252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 56 67 63 0d 20 78 11 c7 f5 e2 67 7c 08 ac 6a ef 9d 7c 25 09 bf 49 c7 66 b6 03 e2 f8 8e 6a ba}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_IO_127749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.IO"
        threat_id = "127749"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Global\\Mila_term" ascii //weight: 1
        $x_1_2 = "RtlAdjustPrivilege" ascii //weight: 1
        $x_1_3 = "OnStartup" ascii //weight: 1
        $x_1_4 = "http://%S%S?aid=%S&ver=%S&uid=%S" ascii //weight: 1
        $x_1_5 = "affid" ascii //weight: 1
        $x_1_6 = "PeekMessageA" ascii //weight: 1
        $x_1_7 = "yandsearch" wide //weight: 1
        $x_1_8 = "Software\\Microsoft\\Internet Explorer\\Main\\" wide //weight: 1
        $x_1_9 = "/l/old.php" wide //weight: 1
        $x_1_10 = "/l/inst.php" wide //weight: 1
        $x_1_11 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\" wide //weight: 1
        $x_1_12 = "{C9C52510-9B41-42c1-9DCD-7282A2D07862}" wide //weight: 1
        $x_1_13 = "m0_glk_110908" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_Y_128082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!Y"
        threat_id = "128082"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 02 eb 01 53 53 ff 75 0c 56 ff 15 ?? ?? ?? ?? 53 8d 45 08 50 6a 0d 57 56 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 0c 92 ff ff ff eb 07 c7 45 0c 5b 00 00 00 50 ff 75 0c ff 75 08 e8}  //weight: 1, accuracy: High
        $x_1_3 = {4e 8a 06 4e 8a 0e 32 c1 3c 22 88 4d 10 77 14 0f b6 d8 53}  //weight: 1, accuracy: High
        $x_1_4 = {e9 93 00 00 00 56 57 6a 0a 59 be ?? ?? ?? ?? 8d 7d a8 f3 a5 6a 29 33 f6}  //weight: 1, accuracy: Low
        $x_1_5 = {74 5a 6a 02 53 68 54 ff ff ff 56 ff 15 ?? ?? ?? ?? 83 f8 ff 74 3f 57 6a 11 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Vundo_IP_128204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.IP"
        threat_id = "128204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 64 6c 6c 00 61 00 62 00 00 00 00 51 00 49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_Z_128665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!Z"
        threat_id = "128665"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {64 ff 35 30 00 00 00 58 c3 00}  //weight: 2, accuracy: High
        $x_1_2 = {66 81 38 4d 5a c3 00 05 00 e8 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {66 81 38 4d 5a [0-3] c3 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_KG_130476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.KG"
        threat_id = "130476"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 e8 06 00 00 00 00 00 00 00 00 00 58 83 c0 08 61 [0-96] cc 62 40 c6 d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_W_130636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!W"
        threat_id = "130636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 c1 c3 e6 5b 55 0f [0-8] 56 57 2b fd 4f 0b f8 5f 57 0f [0-8] 53 50 57}  //weight: 1, accuracy: Low
        $x_1_2 = {64 8b 40 30 52 c1 ca 3c 42 5a 8b 40 0c 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_AN_131726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!AN"
        threat_id = "131726"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 5f 41 30 30 46 25 58 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 76 6d 63 5f 70 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "rundll32.exe \"%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_AB_131764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!AB"
        threat_id = "131764"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {83 e1 00 75 ?? eb 74 70 ?? eb}  //weight: 3, accuracy: Low
        $x_3_2 = {ed ea 2d 00 10 00 00 8b 08 81 e1 ff ff 00 00 31 ?? ?? ?? ?? ?? 81 f9 4d 5a 00 00 0f 85}  //weight: 3, accuracy: Low
        $x_1_3 = "Microsoft Corporation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_KZ_132636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.KZ"
        threat_id = "132636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "GetLastActivePopup" ascii //weight: 10
        $x_10_2 = "InternetReadFile" ascii //weight: 10
        $x_1_3 = "/go/?cmp=" ascii //weight: 1
        $x_1_4 = "uid=%s&guid=%s&vi=%d&ci=" ascii //weight: 1
        $x_1_5 = "dsl_proxy_mutex" ascii //weight: 1
        $x_1_6 = "dsl_rundll_mutex" ascii //weight: 1
        $x_1_7 = {4b d3 91 49 a1 80 91 42 83 b6 33 28 36 6b 90 97}  //weight: 1, accuracy: High
        $x_1_8 = {27 d5 8b 14 ab a2 ce 11 b1 1f 00 aa 00 53 05 03}  //weight: 1, accuracy: High
        $x_1_9 = {0f 84 b1 00 00 00 53 68 80 00 00 00 6a 02 53 6a 03 68 00 00 00 40 ff 75 0c ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_KAM_132774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.KAM"
        threat_id = "132774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 00 f0 ff ff [0-37] 23 c1 [0-64] 2d 00 10 00 00 ?? ?? ?? ?? ?? [0-32] 8b 08 [0-20] 81 e1 ff ff 00 00 81 f9 4d 5a 00 00 0f 85 ?? ff ff ff [0-18] 8d 48 3c 8b 09 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-32] 81 e1 ff ff 00 00 ?? ?? ?? ?? ?? [0-37] 81 f9 50 45 00 00 0f 84 ?? ?? 00 00 [0-32] 33 c0 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {89 55 fc 33 c0 c1 c0 ?? ?? ?? ?? ?? ?? [0-37] 32 02 42 80 3a 00 0f 85 ?? ff ff ff 3b 45 0c 0f 84 ?? 00 00 00 [0-32] 46 [0-32] 3b 73 18 0f 82 ?? ff ff ff [0-255] 83 ec 04 c7 04 24 ?? ?? ?? ?? 81 04 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_AG_133014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!AG"
        threat_id = "133014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6f 00 6e 00 00 00 00 00 47 00 72 00 65 00 65 00 6b 00 20 00 49 00 42 00 4d 00 20 00 33 00 31 00 39 00 20 00 4b 00 65 00 79 00 62 00 6f 00 61 00 72 00 64 00 20 00 4c 00 61 00 79 00 6f 00 75 00 74 00 00 00 64 00 22 00 01 00 46 00 69 00 6c 00 65 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 00 00 00 00 35 00 2e 00 31 00 2e 00 32 00 36 00 30 00 30 00 2e 00 30 00 20 00 28 00 78 00 70 00 63 00 6c 00 69 00 65 00 6e 00 74 00 2e 00 30 00 31 00 30 00 38 00 31 00 37 00 2d 00 31 00 31 00 34 00 38 00 29 00 00 00 40 00 10 00 01 00 49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 6b 00 62 00 64 00 68 00 65 00 33 00 31 00 39 00 20 00 28 00 33 00 2e 00 31 00 31 00 29 00 00 00 80 00 2e 00 01 00 4c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_AH_133128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!AH"
        threat_id = "133128"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" wide //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks" wide //weight: 1
        $x_1_3 = "SYSTEM\\CurrentControlSet\\Control\\Session Manager" wide //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = "Software\\Microsoft\\Internet Explorer\\Main" wide //weight: 1
        $x_1_6 = "Software\\Microsoft\\Security Center\\Svc" wide //weight: 1
        $x_1_7 = "PendingFileRenameOperations2" wide //weight: 1
        $x_1_8 = "SetSecurityDescriptorDacl" ascii //weight: 1
        $x_1_9 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_10 = "UpdatesDisableNotify" wide //weight: 1
        $x_1_11 = "LoadAppInit_DLLs" wide //weight: 1
        $x_1_12 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_13 = {73 75 69 64 3d 00 00 00 26 63 75 69 64 3d 00 00 26 74 69 64 3d 00 00 00 26 6d 6f 72 70 68 5f 69 64 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_AJ_133130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!AJ"
        threat_id = "133130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 81 3e 4d 5a 75 22 8b 46 3c 03 c6 81 38 50 45 00 00 75 15 66 81 48 16 00 20}  //weight: 1, accuracy: High
        $x_1_2 = {66 81 3e 4d 5a 75 23 8b 46 3c 03 c6 81 38 50 45 00 00 75 16 ff 75 08 66 81 48 16 00 20}  //weight: 1, accuracy: High
        $x_1_3 = {b8 4d 5a 00 00 66 39 06 75 26 8b 46 3c 03 c6 81 38 50 45 00 00 75 19 ff 75 08 b9 00 20 00 00 66 09 48 16}  //weight: 1, accuracy: High
        $x_3_4 = {32 04 0e 32 01 32 c3 4b 88 01 49 85 db 7f e2 8b 44 24 10 5f 5e 80 30}  //weight: 3, accuracy: High
        $x_3_5 = {66 81 45 e6 fd ff 8d 45 f4 50 8d 45 e4 50 ff 15 ?? ?? ?? ?? 8d 45 f4 50 50 50 ff 75 08 ff 15}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_AI_133133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!AI"
        threat_id = "133133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 24 ea 15 61 97 [0-64] 81 04 24 f8 16 32 34}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 04 24 06 54 48 35 [0-64] 81 04 24 f8 16 32 34}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 04 24 c5 36 22 49 [0-64] 81 04 24 f8 16 32 34}  //weight: 1, accuracy: Low
        $x_1_4 = {58 4b cf 14 [0-64] 81 ?? 3f fb 9f 41}  //weight: 1, accuracy: Low
        $x_1_5 = {4f 7f a1 0c [0-64] 81 ?? 2d 18 2c a8}  //weight: 1, accuracy: Low
        $x_1_6 = {57 36 7d 7b [0-64] 81 ?? 5b 45 cd 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Vundo_AK_133273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!AK"
        threat_id = "133273"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 03 00 00 00 ?? ?? ?? 5b eb 83 c3 ?? eb ff e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_AM_133876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!AM"
        threat_id = "133876"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {e8 03 00 00 00 ?? ?? ?? 58 eb 83 c0 ?? eb ff e0}  //weight: 2, accuracy: Low
        $x_2_2 = {61 66 66 52 65 66 2e 64 6c 6c 00 61 00 62 00}  //weight: 2, accuracy: High
        $x_1_3 = {03 c1 30 10 0f b6 85 ?? ?? ff ff 41 3b c8 7c df 39 75 ?? 8b 45 ?? 73 03}  //weight: 1, accuracy: Low
        $x_1_4 = {3b c6 74 0e 6a 04 ff 75 0c 53 ff d0 85 c0 0f 95 45 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_JI_134245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.JI"
        threat_id = "134245"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Attempt to use MSIL code" ascii //weight: 1
        $x_1_2 = {56 4d 4d 61 69 6e 4d 75 74 65 78 00 56 43 4d 4d 54 58}  //weight: 1, accuracy: High
        $x_1_3 = {2e 64 6c 6c 00 43 68 65 63 6b 53 61 76 65 00 43 68 65 63 6b 53 74 61 63 6b 00 4f 70 65 6e 53 61 76 65 00 53 68 65 6c 6c 50 61 74 68 00 55 6e 72 65 61 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_KM_137997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.KM"
        threat_id = "137997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {36 61 02 00 00 00 00 00 b9 00 45 78 69 74 50 72 6f 63 65 73 73 00 53 00 43 72 65 61 74 65 46 69 6c 65 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 5d 01 47 65 74 53 79 73 74 65 6d 4d 65 74 72 69 63 73 00 00 99 02 53 79 73 74 65 6d 50 61 72 61 6d 65 74 65 72 73 49 6e 66 6f 41 00 00 00 00 00 00 00 00 00 00 00 00 00 0c 00 41 72 63 54 6f 00 0b 00 41 72 63 00 00 00 00 00 00 00 00 00 00 00 12 00 50 72 69 6e 74 44 6c 67 45 78 57 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {db 3c 87 0c 3e 99 24 5e 0d 1c 06 b7 47 de b3 12 4d c8 43 bb 8b a6 1f 03 5a 7d 09 38 25 1f 5d d4 cb fc 96 f5 45 3b 13 0d 89 0a 1c db ae 32 20 9a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_AP_139297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!AP"
        threat_id = "139297"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 17 33 d2 8b 7d 10 0f bf c2 8d 04 81 31 38 42 66 83 fa 04 72 ee 8b 7d f8 53 8d 45 fc 50 6a 10}  //weight: 2, accuracy: High
        $x_1_2 = {2b f1 3b d0 72 02 33 d2 8a 1c 0e 32 9a ?? ?? ?? ?? 88 19 41 42 4f 75 ea}  //weight: 1, accuracy: Low
        $x_1_3 = {72 2d 6a 14 59 8d 50 ec 3b c8 1b c0 23 c2 50 8b d7 33 c0 e8 ?? ?? ?? ?? 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_KS_139736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.KS"
        threat_id = "139736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 81 f9 4d 5a 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {66 81 39 50 45 0f 85}  //weight: 1, accuracy: High
        $x_1_3 = {81 04 24 a2 81 93 4a}  //weight: 1, accuracy: High
        $x_1_4 = {81 04 24 44 24 45 00}  //weight: 1, accuracy: High
        $x_1_5 = {66 81 38 90 cc 0f 85}  //weight: 1, accuracy: High
        $x_1_6 = {ff 54 24 2c}  //weight: 1, accuracy: High
        $x_1_7 = {81 38 55 8b ec 5d 0f 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_AQ_139780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!AQ"
        threat_id = "139780"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {30 11 ff 45 ?? 39 45 ?? 7c}  //weight: 2, accuracy: Low
        $x_2_2 = {0f b7 40 16 66 a9 00 20 74 09}  //weight: 2, accuracy: High
        $x_1_3 = {75 06 c6 04 32 5c eb 08 3c ?? 75 07 c6 04 32 22}  //weight: 1, accuracy: Low
        $x_1_4 = {d3 f8 47 32 45 0f 88 04 32 42 43 83 fb 04 7c 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_AR_140581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!AR"
        threat_id = "140581"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "wscntfy_mtx" wide //weight: 10
        $x_10_2 = "85.12.43." ascii //weight: 10
        $x_10_3 = "mukozorapa" ascii //weight: 10
        $x_10_4 = "AppInit_DLLs" wide //weight: 10
        $x_1_5 = "/form/index.html" ascii //weight: 1
        $x_1_6 = "uroledup.com" ascii //weight: 1
        $x_1_7 = "Rundll32.exe \"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_LM_140607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.LM"
        threat_id = "140607"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {2f 67 6f 2f 3f 63 6d 70 3d 68 73 74 77 74 63 68 26 76 65 72 3d 00 26 64 3d 00 6c 6f 63 61 6c 68 6f 73 74}  //weight: 20, accuracy: High
        $x_10_2 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 34 00 2e 00 30 00 20 00 28 00 63 00 6f 00 6d 00 70 00 61 00 74 00 69 00 62 00 6c 00 65 00 3b 00 20 00 4d 00 53 00 49 00 45 00 20 00 36 00 2e 00 30 00 29 00 20 00 57 00 69 00 6e 00 4e 00 54 00 20 00 35 00 2e 00 31 00 [0-96] 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 65 00 74 00 63 00 5c 00 68 00 6f 00 73 00 74 00 73 00}  //weight: 10, accuracy: Low
        $x_20_3 = {76 43 8b 4e ?? 83 f9 10 72 1e 8b 03 eb 1c 85 ff 75 ee 83 f8 10 89 7e 14 72 02 8b 1b 5f 8b c6 5e 5d c6 03 00 5b c2 08 00}  //weight: 20, accuracy: Low
        $x_3_4 = "url.adtrgt.com" ascii //weight: 3
        $x_3_5 = "browser-security.microsoft.com" ascii //weight: 3
        $x_3_6 = "82.98.235.133" ascii //weight: 3
        $x_3_7 = "85.12.43.75" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_3_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_KT_140678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.KT"
        threat_id = "140678"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 10 27 00 00 8d 45 e8 50 56 89 75 f4 c7 45 e8 00 1f 0a fa ff d3}  //weight: 2, accuracy: High
        $x_2_2 = {68 c0 d4 01 00 8d 45 e8 50 56 c7 45 e8 80 69 67 ff ff d3}  //weight: 2, accuracy: High
        $x_2_3 = {c7 45 e8 00 98 3b 9e c7 45 ec f7 ff ff ff ff d3}  //weight: 2, accuracy: High
        $x_1_4 = "softnotify.php?" wide //weight: 1
        $x_1_5 = {5a 00 4f 00 52 00 4b 00 41 00 53 00 49 00 54 00 45 00 00 00 5a 00 4f 00 52 00 4b 00 41 00 46 00 45 00 45 00 44 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "FHDTimer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_LN_141702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.LN!dll"
        threat_id = "141702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 6d 6d 69 6f 43 6c 6f 73 65 00 00 00 43 6c 6f 73 65 44 72 69 76 65 72 00 00 00 00 00}  //weight: 10, accuracy: High
        $x_1_2 = {66 81 fa 00 20 0f 94 c0 a3 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 45 f4 c3 cc cc cc}  //weight: 1, accuracy: High
        $x_1_4 = {8b 80 a0 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {81 e5 00 f0 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {81 fd 00 30 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_AT_143490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!AT"
        threat_id = "143490"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 1a 8d 45 84 50 6a 00 8b f1 ff 15 ?? ?? ?? ?? 8d 45 84 50 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 59 6a 08 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {83 f8 50 74 1d 50 8d 45 dc 68 ?? ?? ?? ?? 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {72 02 33 d2 8a 04 0e 32 04 3a 88 01 41 42 4b 75 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Vundo_AU_143572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!AU"
        threat_id = "143572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {76 10 8b 55 08 0f be 02 83 f0 ?? 8b 4d 08 88 01 eb d8}  //weight: 2, accuracy: Low
        $x_2_2 = {75 76 8b 4d 0c 0f b7 71 02 6a 50 e8 ?? ?? ?? ?? 0f b7 d0 3b f2}  //weight: 2, accuracy: Low
        $x_1_3 = {76 6d 63 5f 6d 65 73 73 61 67 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 25 73 5f 5f 63 30 30 25 58 2e}  //weight: 1, accuracy: High
        $x_1_5 = "%s?a=%s&t=%s" ascii //weight: 1
        $x_3_6 = {83 f8 50 74 0b 3d b7 00 00 00 0f 85 b9 00 00 00 ff 45 f8 81 7d f8 c8 00 00 00 7c af e9}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_BL_144344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!BL"
        threat_id = "144344"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 49 4e 4d 4d 2e 64 6c 6c 00 84 00 6d 6d 69 6f 41 64 76 61 6e 63 65 00 8f 00 6d 6d 69 6f 52 65 61 64 00 95 00 6d 6d 69 6f 53 65 74 49 6e 66 6f 00 55 53 45 52 33 32 2e 64 6c 6c 00 be 01 4c 6f 61 64 49 63 6f 6e 41 00 a2 00 44 69 73 70 61 74 63 68 4d 65 73 73 61 67 65 57 00 aa 02 54 72 61 6e 73 6c 61 74 65 4d 65 73 73 61 67 65}  //weight: 10, accuracy: High
        $x_1_2 = {66 81 fb 00 30}  //weight: 1, accuracy: High
        $x_1_3 = {81 e2 ff 0f 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {05 00 06 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {83 65 b0 00}  //weight: 1, accuracy: High
        $x_1_6 = {64 8b 3d 30 00 00 00 eb}  //weight: 1, accuracy: High
        $x_1_7 = {3d 4d 5a 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_LR_144436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.LR!dll"
        threat_id = "144436"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4a 78 69 62 6e 78 77 00 4c 74 6e 6b 72 00 51 6e 77 75 62 77 79 00}  //weight: 1, accuracy: High
        $x_1_2 = "Wuwei.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_BN_144802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!BN"
        threat_id = "144802"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 56 55 4b 2e 64 6c 6c 00 64 00}  //weight: 2, accuracy: High
        $x_2_2 = {c6 45 fc c2 c6 45 fd 10 88 5d fe ff 15 ?? ?? ?? ?? 8b f8 3b fb 0f 84}  //weight: 2, accuracy: Low
        $x_1_3 = {03 40 3c 8b 70 54 2b 70 2c}  //weight: 1, accuracy: High
        $x_1_4 = {8b 48 3c 03 c8 89 4e 14 8b 51 2c 03 d0 8b 41 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_BO_145074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!BO"
        threat_id = "145074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 07 32 c0 e9 dd 00 00 00 8d 45 fc 50 56 56 ff 33 89 75 fc 8b 35 ?? ?? ?? ?? ff d6}  //weight: 1, accuracy: Low
        $x_1_2 = {43 6f 6f 6b 69 65 54 65 72 6d 69 6e 61 74 6f 72 2e 64 6c 6c 00 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_BP_145096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!BP"
        threat_id = "145096"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {64 a1 30 00 00 00 89 45}  //weight: 2, accuracy: High
        $x_2_2 = {32 32 32 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 61 00 73 00}  //weight: 2, accuracy: High
        $x_1_3 = {42 49 4e 52 45 53 00}  //weight: 1, accuracy: High
        $x_1_4 = {42 00 49 00 4e 00 52 00 45 00 53 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_BQ_145414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!BQ"
        threat_id = "145414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b d4 cd 2e 89 (45|85)}  //weight: 3, accuracy: Low
        $x_1_2 = {43 50 4d 2e 64 6c 6c 00 61 00 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {41 56 55 4b 2e 64 6c 6c 00 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {32 32 32 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 61 00 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_MD_145478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.MD"
        threat_id = "145478"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 00 75 00 69 00 64 00 3d 00 25 00 73 00 26 00 63 00 75 00 69 00 64 00 3d 00 25 00 73 00 26 00 61 00 66 00 66 00 69 00 64 00 3d 00 25 00 64 00 26 00 74 00 69 00 64 00 3d 00 25 00 73 00 26 00 63 00 76 00 65 00 72 00 3d 00 25 00 64 00 26 00 6c 00 69 00 3d 00 25 00 64 00 26 00 62 00 69 00 3d 00 25 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {2f 00 70 00 6c 00 64 00 72 00 2f 00 74 00 65 00 73 00 74 00 2e 00 6a 00 70 00 67 00 00 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {4c 53 44 4d 5f 4d 74 78 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_ME_145479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.ME"
        threat_id = "145479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 69 00 65 00 75 00 73 00 65 00 72 00 2e 00 65 00 78 00 65 00 20 00 2d 00 45 00 6d 00 62 00 65 00 64 00 64 00 69 00 6e 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {77 00 73 00 63 00 6e 00 74 00 66 00 79 00 2e 00 65 00 78 00 65 00 00 00 77 00 73 00 63 00 6e 00 74 00 66 00 79 00 5f 00 6d 00 74 00 78 00 00 00 6d 00 72 00 74 00 2e 00 65 00 78 00 65 00 00 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 2d 31 2d 31 2d 30 00 53 2d 31 2d 31 36 2d 34 30 39 36 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_BR_146010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!BR"
        threat_id = "146010"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f 8e e1 00 00 00 89 5d e4 bf ?? ?? ?? ?? eb 03 8b 75 08 89 5d e0 68 ?? ?? ?? ?? 8d 45 a8 89 5d fc e8 e5 03 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = {37 00 37 00 2e 00 37 00 34 00 2e 00 34 00 38 00 2e 00 31 00 31 00 33 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {44 4e 53 43 68 61 6e 67 65 72 57 69 6e 2e 64 6c 6c 00 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_BV_147654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!BV"
        threat_id = "147654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {e8 02 08 00 00 38 5d d3 0f 84 ce 00 00 00 68 ?? ?? ?? ?? 8d 45 d4 e8 13 04 00 00 be ?? ?? ?? ?? 56}  //weight: 2, accuracy: Low
        $x_1_2 = "83.149.115.157" wide //weight: 1
        $x_1_3 = {44 4e 53 43 68 61 6e 67 65 72 57 69 6e 2e 64 6c 6c 00 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_MY_148004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.MY"
        threat_id = "148004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {76 4b 81 79 ?? a2 02 00 00 74 1b 03 09 47 3b fb 72 f0}  //weight: 2, accuracy: Low
        $x_1_2 = "%s%cip=%i.%i.%i.%i&ia=%i&" ascii //weight: 1
        $x_1_3 = "<fix_firewall_rules>" ascii //weight: 1
        $x_1_4 = "%sbin\\javaw.exe -" ascii //weight: 1
        $x_1_5 = {3c 67 65 74 5f 73 79 73 74 65 6d 5f 69 6e 66 6f 3e [0-16] 4f 53 20 76 65 72 73 69 6f 6e 20 25 64 2e 25 64}  //weight: 1, accuracy: Low
        $x_1_6 = "/track.php?a=" ascii //weight: 1
        $x_1_7 = "Global\\xwrapper_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_BW_149779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!BW"
        threat_id = "149779"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 50 ff 30 10 40 4f 75 f7}  //weight: 1, accuracy: High
        $x_1_2 = {74 18 8a 14 38 30 14 31 40 83 f8 20 75 02 33 c0 41 3b 4c 24 04 75 eb}  //weight: 1, accuracy: High
        $x_1_3 = {83 7d e4 05 73 46 8b 45 e4 69 c0 08 02 00 00 05}  //weight: 1, accuracy: High
        $x_1_4 = {49 6e 64 72 61 2e 64 6c 6c 00 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Vundo_AV_155012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!AV"
        threat_id = "155012"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 fa 2e 75 54 8a 51 01 80 ca 20 80 fa 64 75 49 8a 51 02 80 ca 20 80 fa 6c 75 3e 8a 51 03 80 ca 20 80 fa 6c 75}  //weight: 1, accuracy: High
        $x_1_2 = {c1 e8 1f f7 d0 a8 01 74 ?? 81 e7 ff 00 00 00 83 ff 05 72}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b7 04 02 03 c6 33 d2 8b 5d 0c f7 f3 8b f2 89 75 ?? 8a 04 0f 88 45 e7 8a 14 0e 88 14 0f 88 04 0e 47 89 7d ?? 8b 55 ?? eb}  //weight: 1, accuracy: Low
        $x_1_4 = {7d 15 33 c9 8a 4c 05 c4 33 d2 8a 54 05 d4 33 ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Vundo_BX_157551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!BX"
        threat_id = "157551"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 14 88 8b 02 8b f8 33 7d ?? 33 7d ?? 89 45 ?? 89 3a 8b 45 ?? 8d 50 ff c1 ea 02 41 42}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 07 99 59 f7 f9 85 d2 74 24 8b 44 24 ?? 85 c0 75 05 b8}  //weight: 1, accuracy: Low
        $x_1_3 = "x2_alive_mutex" ascii //weight: 1
        $x_1_4 = {70 72 6f 74 65 63 74 2e 64 6c 6c 00 69 6e 73 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Vundo_BY_157552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!BY"
        threat_id = "157552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 b6 1f 00 00 e8 ?? ?? ?? ?? 66 89 45 ?? 6a 00 6a 01 6a 02}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 14 81 89 55 ?? 8b 45 ?? 8b 08 89 4d ?? 8b 55 ?? 33 55 ?? 8b 45 ?? 33 10}  //weight: 1, accuracy: Low
        $x_1_3 = "x2_shared" ascii //weight: 1
        $x_1_4 = {78 32 2e 64 6c 6c 00 69 6e 73 74 61 6c 6c 00 70 6f 70 75 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Vundo_BZ_157553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!BZ"
        threat_id = "157553"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 04 8a 89 45 ?? 8b 4d ?? 8b 11 89 55 ?? 8b 45 ?? 33 45 ?? 8b 4d ?? 33 01}  //weight: 1, accuracy: Low
        $x_1_2 = {75 1a 8d 95 e8 fd ff ff 52 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 3f 8b 85 6c f3 ff ff 50 ff 15 ?? ?? ?? ?? 85 c0 75 0c c7 85 ?? ?? ?? ?? ?? ?? ?? ?? eb 0a}  //weight: 1, accuracy: Low
        $x_1_4 = "x2_alive_mutex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Vundo_AW_161152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!AW"
        threat_id = "161152"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 11 39 55 08 73 05 89 55 08 8b c7 47 83 c1 10 3b fb 72 ?? 83 f8 ff 74 ?? c1 e0 04 03 c6 33 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 d4 6a 00 2b ce 68 80 96 98 00 1b c2 50 51}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_OB_162787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.OB"
        threat_id = "162787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {40 3b c1 a3 ?? ?? ?? ?? 72 2a 00 32 ?? 88 ?? ?? 8b ?? ?? ?? ?? ?? ?? 83 ?? 10 89 ?? ?? ?? ?? ?? 75 08 33 ?? 89 ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b}  //weight: 4, accuracy: Low
        $x_1_2 = {3d 0e 27 00 00 0f 86 ?? ?? ?? ?? ff d6 0a 00 33 (d1|ca) 89 (50|48) 0c}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 64 6c 6c 00 4f 72 64 69 6e 61 6c 31 00 4f 72 64 69 6e 61 6c 32 00 66 4f 72 64 63 68 6b}  //weight: 1, accuracy: High
        $x_1_4 = {5f 63 72 79 70 74 65 64 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_OD_163836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.OD"
        threat_id = "163836"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 45 fc 6a 08 59 6b c0 0d 05 ?? ?? ?? ?? 49 0f c8 75 ?? 6a 07 59 33 d2 6a 1a 5f f7 f7 80 c2 61 88 16 46 49 75 ?? 5f c7 06 2e 64 6c 6c}  //weight: 4, accuracy: Low
        $x_2_2 = {63 3a 5c 00 66 6c 61 73 68 5f 70 6c 61 79 65 72 5f 75 70 64 61 74 65 2e 65 78 65 00 72 75 6e 61 73}  //weight: 2, accuracy: High
        $x_2_3 = {2f 63 68 6b 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 64 6f 77 73}  //weight: 2, accuracy: High
        $x_1_4 = "AppInit_DLLs" ascii //weight: 1
        $x_1_5 = "LoadAppInit_DLLs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_OH_164751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.OH"
        threat_id = "164751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {8b c1 c1 e8 10 c1 e1 10 0b c1 89 45 ?? 2d ?? ?? 00 00 89 45 ?? 8b c8 c1 e9 1c c1 e0 04 0b c8 89 4d ?? 33 ca 89 4d ?? 89 0c 96 42 eb}  //weight: 8, accuracy: Low
        $x_4_2 = {0f 85 a8 00 00 00 81 f9 c6 74 8c 3d 0f 84 c5 00 00 00 81 f9 25 19 fa b6 0f 84 b9 00 00 00 81 f9 a1 b7 ad b8}  //weight: 4, accuracy: High
        $x_4_3 = {8b f9 c1 ef 17 c1 e1 09 0b cf 89 4d ?? 81 e9 ?? ?? ?? 00 89 4d ?? 0f b6 d2 2b ca e9}  //weight: 4, accuracy: Low
        $x_2_4 = {00 80 55 aa 68 1c 27 c0 00 20 4c aa 93 8c 2f ea 13 8c 26 e5 45 09}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_AX_165191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!AX"
        threat_id = "165191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ec b4 00 00 00 8d 44 24 ?? 56 6a 64 50 6a 6a 51 ff 15 ?? ?? ?? ?? 8b b4 24 ?? 00 00 00 8b c6 83 e8 02 0f 84 ?? ?? ?? ?? 83 e8 0d 0f 84 ?? ?? ?? ?? 2d 02 01 00 00 74 ?? 68}  //weight: 1, accuracy: Low
        $x_1_2 = {83 ec 1c 56 8b 74 24 ?? 57 8b 3d ?? ?? ?? ?? 6a ?? 68 ?? ?? ?? ?? 6a ?? 56 ff d7 6a ?? 68 ?? ?? ?? ?? 6a ?? 56 ff d7 56 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {53 56 57 6a 59 ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 2b ce 03 c1 a3 ?? ?? ?? ?? 74 ?? 8b 15 ?? ?? ?? ?? 6a 00 6a 00 6a 02 52 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_OT_167716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.OT"
        threat_id = "167716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c9 03 d1 8b ca c1 e9 0f c1 e2 11 0b ca 81 c1 ?? ?? ?? 00 8b d1 8a 08 40 40 84 c9}  //weight: 1, accuracy: Low
        $x_1_2 = {2b c7 8b 34 38 8b dd 83 e3 1f 6a 20 59 2b cb 8b d6 d3 e2 8b cb d3 ee 0b d6 81 c2 ?? ?? 00 00 8b ca c1 e1 14 c1 ea 0c 0b ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_OV_167767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.OV"
        threat_id = "167767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 61 63 75 75 72 65 2e 64 6c 6c 00 61 63 43 6c 69 65 6e 74}  //weight: 1, accuracy: High
        $x_1_2 = {8b 48 28 85 c9 74 14 a1 ?? ?? ?? ?? 6a 00 03 c8 6a 02 50 89 0d ?? ?? ?? ?? ff d1}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4d fc 66 83 79 0c 08 74 05 b8 06 00 00 00 85 c0 75 0c 8d 55 f8 52 ff 73 08 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Vundo_CA_169244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!CA"
        threat_id = "169244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 14 8d e0 a4 01 10 0e 00 74 09 8b 45 fc 83 c0 06 89 45 fc 8b 4d fc}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 14 8d 60 52 01 10 0e 00 74 09 8b 45 fc 83 c0 06 89 45 fc 8b 4d fc}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 14 85 00 b0 01 10 09 00 74 04 83 45 fc 06 8b 45 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Vundo_PD_169600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.PD"
        threat_id = "169600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 00 2d 8b 00 00 00 85 c0 74 18}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 40 01 8b 0d ?? ?? ?? ?? 0f b6 49 0e 2b c1 85 c0 ?? 0f}  //weight: 1, accuracy: Low
        $x_1_3 = {33 c1 8b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 88 01 e9 15 00 8a 00 a2 ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 0f b6 0d}  //weight: 1, accuracy: Low
        $x_1_4 = {8a 00 32 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 88 01 a1 ?? ?? ?? ?? 25 f0 01 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {c6 86 08 00 00 00 56 a3 ?? ?? ?? ?? c6 86 09 00 00 00 69}  //weight: 1, accuracy: Low
        $x_1_6 = {0f b7 45 10 83 e8 68 0f 84 ?? ?? ?? ?? 48 74 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Vundo_PF_170322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.PF"
        threat_id = "170322"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "VXMOST_INSTALL_" ascii //weight: 1
        $x_1_2 = "C6869367-9A6F-4A4F-B38C-F442B110B07D-9759A32A-AF94-4354-8CC8-4EE66E0CC778-89E52177-C136-4112-A5D6-16C7E57DCCE2" ascii //weight: 1
        $x_1_3 = {83 ef 08 8b cf 8b 5d ec d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 ec 5a 8b ca 99 f7 f9 89 55 ec 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 8d 45 e4 8b d3 e8}  //weight: 1, accuracy: High
        $x_1_4 = {56 6a 00 68 ff 0f 1f 00 e8 ?? ?? ?? ?? 6a ff 50 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 3c 08 73 52 6a 00 8d 55 d0 b8 02 00 00 00 e8 ?? ?? ?? ?? 8b 45 d0 e8 ?? ?? ?? ?? 50 8d 55 cc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_PG_170323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.PG"
        threat_id = "170323"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "29877039-4D14-4136-8D00-392BC81D9C36" ascii //weight: 1
        $x_1_2 = "3A884AA3-0594-48FC-BF95-4C69A51A3787" ascii //weight: 1
        $x_1_3 = "KillFiles" ascii //weight: 1
        $x_1_4 = "DeleteFiles" ascii //weight: 1
        $x_1_5 = {8d 45 f8 ba b0 3d 41 00 e8 ?? ?? ?? ?? 6a 00 68 ?? ?? ?? 00 ff 75 f8 68 ?? ?? ?? 00 ff 75 fc 68 ?? ?? ?? 00 8d 45 f4 ba 05 00 00 00 e8 ?? ?? ?? ?? 8b 45 f4 e8 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 85 8c fe ff ff ba b8 40 41 00 e8 ?? ?? ?? ?? 74 56 8d 95 88 fe ff ff 8b 45 f4 e8 ?? ?? ?? ?? 8b 85 88 fe ff ff ba c4 40 41 00 e8 ?? ?? ?? ?? 74 36 ff 75 f8 68 ?? ?? ?? 00 ff b5 a8 fe ff ff 8d 85 84 fe ff ff ba 03 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_PK_171206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.PK"
        threat_id = "171206"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 00 2d ?? 00 00 00 85 c0 74}  //weight: 1, accuracy: Low
        $x_10_2 = {8a 23 93 32 df 93 88 03}  //weight: 10, accuracy: High
        $x_1_3 = {0f b6 00 83 e8 ?? 85 c0 74 0b 00 a1 ?? ?? ?? ?? 2b 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_PR_172679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.PR"
        threat_id = "172679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d3 c0 28 06 46}  //weight: 1, accuracy: High
        $x_1_2 = "software\\microsoft\\windows\\currentversion\\run" ascii //weight: 1
        $x_1_3 = "TFakeReferrer" ascii //weight: 1
        $x_1_4 = {54 72 65 6e 64 4d 69 63 72 6f 00}  //weight: 1, accuracy: High
        $x_1_5 = ".googleadservices." wide //weight: 1
        $x_1_6 = "enterprise_web_store" wide //weight: 1
        $x_1_7 = {d3 c0 28 07 47 e2 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Vundo_AZ_173284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!AZ"
        threat_id = "173284"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 04 83 04 24 06 8b 04 24 8b 0c 85 68 31 01 10 ff d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_CB_173302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!CB"
        threat_id = "173302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 04 83 45 fc 06 8b 45 fc ff 14 85 ?? ?? (00|01|02) 10}  //weight: 1, accuracy: Low
        $x_1_2 = {10 ff d0 59 0a 00 89 ?? ?? (4f|4e|49) 79 ?? 68 ?? ?? (01|00)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_QA_174089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.QA"
        threat_id = "174089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 c9 0d 66 19 00 81 c1 5f f3 6e 3c 30 0c 3e}  //weight: 1, accuracy: High
        $x_1_2 = {fa 31 e8 67 4d ad 67 83 d8 69 ed df f2 65 fb 7b ea a1 af 57 aa 1d 0b 73 41 d9 91 cf}  //weight: 1, accuracy: High
        $x_1_3 = {88 cb 6e 71 bf a7 09 ed 2a c3 ab a9 80 1f a5 a5 b8 bb a9 e1 78 97 25 5d 53 b3 d7 19}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Vundo_QA_174089_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.QA"
        threat_id = "174089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\windows\\currentversion\\run" wide //weight: 1
        $x_1_2 = "\\Windows NT\\CurrentVersion\\Win" wide //weight: 1
        $x_1_3 = "AppInit_DLLs" wide //weight: 1
        $x_1_4 = ".php?num=%s&rev=%s&os=%s" wide //weight: 1
        $x_1_5 = "ftp*commander*" wide //weight: 1
        $x_1_6 = ".php?rev=%s&code=%s&" wide //weight: 1
        $x_1_7 = "&ref=%s&real_refer=%s" wide //weight: 1
        $x_1_8 = "%APPDATA%\\Opera" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Vundo_CC_174100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!CC"
        threat_id = "174100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 fa 27 86 53 fb 74 44}  //weight: 1, accuracy: High
        $x_1_2 = {b8 00 10 00 00 50 50 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {83 e1 1f d3 c6 81 ee 63 1a 00 00 89 34 90 4a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_CD_174190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!CD"
        threat_id = "174190"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff d7 46 eb cd c7 45 ?? ff ff ff ff be 01 00 00 00 89 75 fc f6 40 17 20 8b 40 28 74 ?? 03 c3 89 45 ?? 8b 55 08 52 56 53 ff d0}  //weight: 2, accuracy: Low
        $x_1_2 = {8d 8c 08 90 90 90 90 89 4b 0c 31 0b 8b 4b 0c 31 4b 04 8b 53 0c 31 53 08 eb 09}  //weight: 1, accuracy: High
        $x_1_3 = {83 fa 3c 72 38 81 fa 00 00 20 00 77 30 8d 41 1c 89 45 e4 39 10 75 26}  //weight: 1, accuracy: High
        $x_1_4 = {7d 2d 8b bd ?? ?? ff ff 81 c7 ?? ?? ?? ?? 89 bd ?? ?? ff ff 0f be f0 33 d2 8a 96 ?? ?? ?? ?? 03 d7 88 54 35 ?? fe c0 88 85 ?? ?? ff ff eb cb}  //weight: 1, accuracy: Low
        $x_1_5 = {73 30 0f b7 c9 8b f1 c1 ee 0e c1 e1 02 33 ce 89 8d ?? ?? ff ff 0f b6 f0 33 db 8a 9e ?? ?? ?? ?? 2b d9 88 5c 35 ?? fe c0 88 85 ?? ?? ff ff 33 db eb cc}  //weight: 1, accuracy: Low
        $x_1_6 = {73 2e 8b f0 c1 e6 17 c1 e8 09 0b c6 89 85 ?? ?? ff ff 0f b6 f1 33 db 8a 1c b5 ?? ?? ?? ?? 2b d8 88 5c 35 ?? fe c1 88 8d ?? ?? ff ff 33 db eb ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_QB_174219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.QB"
        threat_id = "174219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "adfclick;all.html;article.asp;BoxRedirect.shtml;" ascii //weight: 1
        $x_1_2 = "refererPage;REFERRALID;RMID;RNLBSERVERID;ruid;rvd;S;s;SBSESSIONID;SESSID;" ascii //weight: 1
        $x_10_3 = {80 bc 05 c3 fe ff ff 5c 75 1d 8d 85 ?? fe ff ff 8d 50 01 8d 64 24 00 8a 08 40 84 c9 75 f9 2b c2 88 8c 05 c3 fe ff ff 8d 8d ?? fe ff ff e8 95 fe ff ff 89 85 ?? fe ff ff 89 95 ?? fe ff ff}  //weight: 10, accuracy: Low
        $x_10_4 = {52 6a 06 56 ff 15 ?? ?? ?? ?? 89 5d e4 6a 04 8d 45 e4 50 6a 07 56 ff 15 ?? ?? ?? ?? 89 7d e4 6a 04 8d 4d e4 51 6a 05 56 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_CE_174276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!CE"
        threat_id = "174276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 7d 0c dc 07 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {81 c7 08 a0 00 00 89 3d ?? ?? ?? ?? be 60 ae 0a 00}  //weight: 1, accuracy: Low
        $x_1_3 = {08 a0 00 00 c7 45 0c 60 ae 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_QF_174517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.QF"
        threat_id = "174517"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "vmzcdlkx_sjklmde" wide //weight: 2
        $x_2_2 = "93jdsleJdnskl:" wide //weight: 2
        $x_1_3 = {ff ff 00 45 00 00 7d}  //weight: 1, accuracy: High
        $x_1_4 = {ff ff a0 86 01 00 0f 8d}  //weight: 1, accuracy: High
        $x_1_5 = {ff ff 90 d0 03 00 0f 87}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_CF_175484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.gen!CF"
        threat_id = "175484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c1 c1 e8 08 80 f9 c0 75 ?? 3c a8 74}  //weight: 5, accuracy: Low
        $x_1_2 = {8b 08 50 1b db ff 51 28 3b}  //weight: 1, accuracy: High
        $x_1_3 = {8b 08 1b db 50 8b eb ff 51 28 3b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_RT_198877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.RT"
        threat_id = "198877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 7d fc 3c 21 2d 2d 74}  //weight: 1, accuracy: High
        $x_1_2 = {81 3c 10 8b ff 55 8b 74 0d 41 83 f9 12 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_RU_200106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.RU"
        threat_id = "200106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\MyApplicationData\\~backup.exe" ascii //weight: 1
        $x_1_2 = "Host: metrika.yandex.ru" ascii //weight: 1
        $x_1_3 = "&digital=x86" ascii //weight: 1
        $x_1_4 = "&digital=x64" ascii //weight: 1
        $x_1_5 = {3c 73 63 72 69 70 74 20 73 72 63 3d 22 68 74 74 70 3a 2f 2f 67 6f 6f 67 6c 65 2e 72 75 2f 6a 73 22 3e 3c 2f 73 63 72 69 70 74 3e 00}  //weight: 1, accuracy: High
        $x_1_6 = {7e 74 65 6d 70 62 61 63 6b 75 70 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {7e 64 77 6e 6c 64 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_3_8 = {56 ff d3 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff d3 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff d3 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff d3 a1 ?? ?? ?? ?? 33 c9 3b c7 76 ?? 8b 15 ?? ?? ?? ?? 0f b6 14 0a 01 15 ?? ?? ?? ?? 41 3b c8 72}  //weight: 3, accuracy: Low
        $x_2_9 = {68 2c 0f 00 00 56 56 e8 ?? ?? ?? ?? 53 68 28 09 00 00 56 56 e8 ?? ?? ?? ?? 83 c4 20 39 3e 74 25 53 b8 ?? ?? ?? ?? 68 2c 0f 00 00 50 50 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_RV_200952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.RV"
        threat_id = "200952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 00 01 00 6a 00 8d 85 ?? ?? fe ff 50 e8 ?? ?? ?? ?? 83 c4 0c 8d 8d ?? ?? fe ff 51 8b 95 ?? ?? fe ff 52 8d 85 ?? ?? fe ff 50 8b 8d ?? ?? ff ff 51 ff 95 ?? ?? fe ff}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 02 8b 85 ?? ?? ff ff 50 ff 55 ?? 85 c0 75 12 ff 15 ?? ?? ?? ?? 83 f8 7a 74 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_RW_202616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.RW"
        threat_id = "202616"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<script src=\"http://google.ru/js" ascii //weight: 1
        $x_1_2 = "Expires: %s, %02d %s %04d 23:59:59 GMT" ascii //weight: 1
        $x_1_3 = "User-Agent: Test Agent" ascii //weight: 1
        $x_1_4 = "/file/upload.php" ascii //weight: 1
        $x_1_5 = "default.cfg" ascii //weight: 1
        $x_2_6 = "metrika.yandex.ru" ascii //weight: 2
        $x_3_7 = {81 e1 00 f0 00 00 bb 00 30 00 00 66 3b cb 75 1f}  //weight: 3, accuracy: High
        $x_3_8 = {57 8b 7d 10 83 c7 07 c1 ef 03 4f}  //weight: 3, accuracy: High
        $x_1_9 = {5b 43 4f 4f 4b 5d 00 00 5b 52 45 4e 54 5d 00 00 5b 52 50 4c 5d 00 00 00 3c 2f 73 63 72 69 70 74 3e}  //weight: 1, accuracy: High
        $x_1_10 = {5b 52 52 5d 00 00 00 00 5b 55 42 4d 50 5d 00 00 5b 55 44 4c 4c 5d 00 00 5b 44 4c 4c 5d 00 00 00 5b 44 41 53 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vundo_RZ_223142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.RZ"
        threat_id = "223142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d1 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 b2 e9 38 53 08 75 10 83 7b 04 05 75 0a}  //weight: 1, accuracy: High
        $x_1_2 = {b2 7c 8b ce e8 ?? ?? ?? ?? 85 c0 7f 75}  //weight: 1, accuracy: Low
        $x_1_3 = {33 c9 8a 0c 37 33 c1 88 04 37 46 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Vundo_SA_223571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.SA"
        threat_id = "223571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 58 83 e8 05 50 e8 ?? ?? 00 00 8b 54 24 04 0f b6 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {68 2d 2e 10 9b e8 ?? ff ff ff 85 c0 59 89 45 f4 74 12 68 ff 1f 7c c9 e8 ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {68 4a 0d ce 09 e8 ?? ff ff ff 85 c0 59 74 0f 6a 04 68 00 30 00 00 ff 74 37 50 6a 00 ff d0}  //weight: 1, accuracy: Low
        $x_1_4 = {74 13 8b 7d 0c 2b fe 89 4d 08 8a 0b 88 0c 1f 43 ff 4d 08 75 f5 83 65 08 00 66 83 7a 06 00 76 31}  //weight: 1, accuracy: High
        $x_1_5 = {ff 55 f4 85 c0 89 45 fc 74 3c 8b 7c 33 10 03 fe eb 1d 79 07 25 ff ff 00 00 eb 04 8d 44 30 02 50 ff 75 fc ff 55 f8}  //weight: 1, accuracy: High
        $x_1_6 = {8d 45 f4 50 ff 77 1c e8 ?? ff ff ff 59 50 8b 47 04 ff 37 03 c3 50 ff 55 f8 0f b7 46 06 ff 45 fc 83 c7 28 39 45 fc 72 d8}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 7c 30 28 85 ff 59 59 74 27 68 dd f5 53 cd e8 ?? ?? ff ff 85 c0 59 74 18}  //weight: 1, accuracy: Low
        $x_1_8 = {53 8b 5c 24 08 57 8d bb ?? ?? 00 00 66 81 3f 4d 5a 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Vundo_CA_334045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.CA!MTB"
        threat_id = "334045"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba e2 7f 9c d5 30 10 40 49 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {8b df 2b d8 8a 03 88 07 47 bb 02 00 00 00 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_AHB_464693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.AHB!MTB"
        threat_id = "464693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c1 e1 08 0f b6 d4 0f b6 85 32 fb ff ff 03 ca 0f b6 95 33 fb ff ff c1 e1 08 03 c8 c1 e1 08 03 ca 89 4e fe 83 c4 0c 83 c6 08 83 ef 01 0f 85}  //weight: 10, accuracy: High
        $x_5_2 = {03 d3 c1 fa 03 8b c2 c1 e8 1f 03 c2 8b c8 c1 e1 04 2b c8 8b d3 2b d1 0f be 8c 15 34 ff ff ff 8d b4 15 34 ff ff ff b8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_GVA_472150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.GVA!MTB"
        threat_id = "472150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 d2 8a d4 89 15 98 19 01 01 8b c8 81 e1 ff 00 00 00 89 0d 94 19 01 01 c1 e1 08 03 ca 89 0d 90 19 01 01 c1 e8 10 a3 8c 19 01 01 33 f6}  //weight: 2, accuracy: High
        $x_1_2 = {8a 50 01 40 80 fa 22 74 29 84 d2 74 25 0f b6 d2 f6 82 61 1c 01 01 04 74 0c ff 01 85 f6 74 06 8a 10 88 16 46 40 ff 01 85 f6 74 d5 8a 10 88 16 46 eb ce}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vundo_AHC_474172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vundo.AHC!MTB"
        threat_id = "474172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {8a 10 80 f2 ?? 66 0f b6 d2 0f b7 d2 88 10 41 8b c1 80 39 ?? 75}  //weight: 30, accuracy: Low
        $x_20_2 = {32 14 2f 8b 4c 24 14 8d 34 85 ?? ?? ?? ?? 33 f0 03 f6 22 d9 33 f0 32 d3 32 d0}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

