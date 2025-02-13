rule Trojan_Win32_Virtumonde_O_111416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Virtumonde.O"
        threat_id = "111416"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Virtumonde"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {56 4d 44 6c 6c 2e 64 6c 6c 00 66 6f 72 6b 00 66 6f 72 6b 6f 6e 63 65}  //weight: 10, accuracy: High
        $x_10_2 = "Local_AfSysUpd" wide //weight: 10
        $x_10_3 = "Local_AfMainMutex" wide //weight: 10
        $x_1_4 = "www.traffic-converter.com" ascii //weight: 1
        $x_1_5 = "www.7adpower.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Virtumonde_O_111416_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Virtumonde.O"
        threat_id = "111416"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Virtumonde"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 72 65 61 6c 67 6f 00 72 65 61 6c 73 65 74}  //weight: 2, accuracy: High
        $x_2_2 = {56 4d 44 6c 6c 2e 64 6c 6c 00 66 6f 72 6b 00 66 6f 72 6b 6f 6e 63 65}  //weight: 2, accuracy: High
        $x_2_3 = {56 4d 44 6c 6c 2e 64 6c 6c 00 73 69 74 79 70 00 73 69 74 79 70 6e 6f 77}  //weight: 2, accuracy: High
        $x_1_4 = {2e 64 6c 6c 00 61 00 62}  //weight: 1, accuracy: High
        $x_1_5 = "64.235.246.150;www.zestyfind" wide //weight: 1
        $x_10_6 = "p://makenow.net:80)" wide //weight: 10
        $x_10_7 = "66.220.17.157;search" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Virtumonde_O_111416_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Virtumonde.O"
        threat_id = "111416"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Virtumonde"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "63"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ";Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" wide //weight: 10
        $x_10_2 = "Local\\ReadURLListTimer" wide //weight: 10
        $x_10_3 = "Local_AfSysUpdConnectTimer" wide //weight: 10
        $x_10_4 = "Protection thread" wide //weight: 10
        $x_10_5 = "Registry thread" wide //weight: 10
        $x_10_6 = "StopAndRecover thread" wide //weight: 10
        $x_1_7 = ".targetnet.com;" wide //weight: 1
        $x_1_8 = "www.emarketmakers.com" wide //weight: 1
        $x_1_9 = "azoogleads.com;" wide //weight: 1
        $x_1_10 = "www.traffic-converter.com;" wide //weight: 1
        $x_1_11 = "infinite-ads.com;" wide //weight: 1
        $x_1_12 = "www.7adpower.com;" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Virtumonde_114805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Virtumonde"
        threat_id = "114805"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Virtumonde"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "54"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Windows NT\\CurrentVersion\\Winlogon\\Notify\\" ascii //weight: 10
        $x_10_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 10
        $x_10_3 = "PendingFileRenameOperations" ascii //weight: 10
        $x_10_4 = "Asynchronous" ascii //weight: 10
        $x_5_5 = {2e 64 6c 6c 00 49 6e 73 74 61 6c 6c 00 4f 66 66 45 76 65 6e 74 00 4f 6e 45 76 65 6e 74 00 51 75 65 72 79 53 74 61 72 74 53 65 71 75 65 6e 63 65}  //weight: 5, accuracy: High
        $x_5_6 = {53 65 74 56 4d 00 53 79 73 4c 6f 67 6f 66 66 00 53 79 73 4c 6f 67 6f 6e}  //weight: 5, accuracy: High
        $x_5_7 = {25 30 38 78 5f 5f 5f 31 32 32 00 00}  //weight: 5, accuracy: High
        $x_1_8 = "insmutanhokueergsdlds" ascii //weight: 1
        $x_1_9 = "bush_ssevent" ascii //weight: 1
        $x_1_10 = "klinton_ssmmf" ascii //weight: 1
        $x_1_11 = "BPCrush" ascii //weight: 1
        $x_1_12 = "ANTISPYWARE?GCASSERVALERT.EXE" ascii //weight: 1
        $x_1_13 = "PopupsShown=%i;MaxPopupPerDay=%i" ascii //weight: 1
        $x_1_14 = "SysProtect\\ActivationCode" ascii //weight: 1
        $x_1_15 = "WinSoftware\\Winantivirus 2005\\ActivationCode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Virtumonde_M_116855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Virtumonde.M"
        threat_id = "116855"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Virtumonde"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "startwatcher" ascii //weight: 1
        $x_1_2 = {73 79 73 74 65 6d 32 2e 64 6c 6c 00 77 61 74 63 68 64 6c 6c 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_3 = "d:\\#development\\__tasks\\Watcher_bundle\\" ascii //weight: 1
        $x_1_4 = {77 61 74 63 68 65 72 5f 62 75 6e 64 6c 65 2e 64 6c 6c 00 53 74 61 72 74 75 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Virtumonde_M_116855_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Virtumonde.M"
        threat_id = "116855"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Virtumonde"
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
        $x_1_28 = "winlogon.exe" ascii //weight: 1
        $x_1_29 = "winpopupguard.com" ascii //weight: 1
        $x_1_30 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_31 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify" ascii //weight: 1
        $x_1_32 = {43 72 65 61 74 65 4d 61 69 6e 50 72 6f 63 00 43 72 65 61 74 65 50 72 6f 74 65 63 74 50 72 6f 63}  //weight: 1, accuracy: High
        $x_1_33 = {52 65 61 6c 4c 6f 67 6f 66 66 00 52 65 61 6c 4c 6f 67 6f 6e}  //weight: 1, accuracy: High
        $x_1_34 = "#'yu[QV9w!>-6G.4tg`xnkdE$~Arf&I?_|qm\\NCST:/bKaH2Z=c" ascii //weight: 1
        $x_1_35 = "+6Zrp*S2u)v_l/e1R%z@L(s[WVnOax'FPEAIQ}HT?fU]BmY~M0dbt3" ascii //weight: 1
        $x_1_36 = "yPo0q-uz(JXiR+@l;eG\\8x.O?UM|dFgr&~HI`'VshQ%EZYA3NLS7W=2paw6{D5^]C<}1$_)4#jbBv:T" ascii //weight: 1
        $x_1_37 = {61 77 78 5f 6d 75 74 61 6e 74 00 00 61 64 2d 61 77 61 72 65 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_38 = {73 73 77 5f 6d 75 74 61 6e 74 00 00 77 72 73 73 73 64 6b 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_39 = {68 6a 74 5f 6d 75 74 61 6e 74 00 00 68 69 6a 61 63 6b 74 68 69 73 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (30 of ($x*))
}

