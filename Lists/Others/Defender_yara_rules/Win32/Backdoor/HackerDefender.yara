rule Backdoor_Win32_HackerDefender_2147680285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/HackerDefender"
        threat_id = "2147680285"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "HackerDefender"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "208"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
        $x_100_2 = "\\\\.\\yspy000" ascii //weight: 100
        $x_1_3 = "-:INSTALLONLY" ascii //weight: 1
        $x_1_4 = "-:REFRESH" ascii //weight: 1
        $x_1_5 = "-:NOSERVICE" ascii //weight: 1
        $x_1_6 = "-:UNINSTALL" ascii //weight: 1
        $x_1_7 = "[HTABLE]" ascii //weight: 1
        $x_1_8 = "[HPROCESSES]" ascii //weight: 1
        $x_1_9 = "[HSERVICES]" ascii //weight: 1
        $x_1_10 = "[HREGKEYS]" ascii //weight: 1
        $x_1_11 = "[HPORTS]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_HackerDefender_2147680285_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/HackerDefender"
        threat_id = "2147680285"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "HackerDefender"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2422"
        strings_accuracy = "High"
    strings:
        $x_1000_1 = "TCustomMemoryStream" ascii //weight: 1000
        $x_1000_2 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\" ascii //weight: 1000
        $x_100_3 = "SetSecurityDescriptorDacl" ascii //weight: 100
        $x_100_4 = "AddAccessAllowedAce" ascii //weight: 100
        $x_100_5 = "DisconnectNamedPipe" ascii //weight: 100
        $x_100_6 = "CreateMailslotA" ascii //weight: 100
        $x_10_7 = "Comspec" ascii //weight: 10
        $x_10_8 = "/c del \"" ascii //weight: 10
        $x_1_9 = "svchost.exe" ascii //weight: 1
        $x_1_10 = "r_server.exe" ascii //weight: 1
        $x_1_11 = "SYSTEM\\CurrentControlSet\\Services\\r_server" ascii //weight: 1
        $x_1_12 = "/pass:" ascii //weight: 1
        $x_1_13 = "/port:" ascii //weight: 1
        $x_1_14 = "Radmin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1000_*) and 4 of ($x_100_*) and 2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_HackerDefender_2147680285_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/HackerDefender"
        threat_id = "2147680285"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "HackerDefender"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "351"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
        $x_100_2 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c [0-10] 2d ?? ?? 31 30 30}  //weight: 100, accuracy: Low
        $x_100_3 = "[Hacker Defender]" ascii //weight: 100
        $x_10_4 = "SeDebugPrivilege" ascii //weight: 10
        $x_10_5 = "SeLoadDriverPrivilege" ascii //weight: 10
        $x_10_6 = "NtQuerySystemInformation" ascii //weight: 10
        $x_10_7 = "NtLoadDriver" ascii //weight: 10
        $x_10_8 = "NtQueryObject" ascii //weight: 10
        $x_1_9 = "loplop.ini" ascii //weight: 1
        $x_1_10 = "Alerter" ascii //weight: 1
        $x_1_11 = "lop_b.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_HackerDefender_2147680285_3
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/HackerDefender"
        threat_id = "2147680285"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "HackerDefender"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\\\.\\HxDefDriver" ascii //weight: 2
        $x_2_2 = "\\\\.\\mailslot\\hxdef-rk100s" ascii //weight: 2
        $x_2_3 = "\\\\.\\mailslot\\hxdef-rk100s0ACEE761" ascii //weight: 2
        $x_2_4 = "Prefetch\\*.pf" ascii //weight: 2
        $x_2_5 = "\\\\.\\mailslot\\hxdef-rkc" ascii //weight: 2
        $x_2_6 = "\\\\.\\mailslot\\hxdef-rkb" ascii //weight: 2
        $x_2_7 = "\\\\.\\mailslot\\hxdef-rks" ascii //weight: 2
        $x_2_8 = "-:bd:-" ascii //weight: 2
        $x_2_9 = "-:INSTALLONLY" ascii //weight: 2
        $x_2_10 = "-:REFRESH" ascii //weight: 2
        $x_2_11 = "-:NOSERVICE" ascii //weight: 2
        $x_2_12 = "-:UNINSTALL" ascii //weight: 2
        $x_2_13 = "-:BD:-" ascii //weight: 2
        $x_2_14 = "GHandles v1.0 for GKit by gray,thx for Holy_Father && Ratter/29A" ascii //weight: 2
        $x_5_15 = "\\DosDevices\\HxDefDriver" wide //weight: 5
        $x_5_16 = "\\Device\\HxDefDriver" wide //weight: 5
        $x_3_17 = "ZwDuplicateToken" ascii //weight: 3
        $x_3_18 = "ZwOpenProcessToken" ascii //weight: 3
        $x_5_19 = {8b 4d e8 89 4d f4 c7 45 f8 00 00 00 00 8d 55 f4 52 8d 45 d0 50 68 ff 0f 1f 20 00 8d 4d a0 51 ff 15}  //weight: 5, accuracy: High
        $x_5_20 = {ff 75 f0 ff 15 f4 07 01 00 85 c0 7c 4d 8d 45 d0 50 6a 01 8d 45 b8 53 50 68 ff 00 0f 00 ff 75 0c ff 15}  //weight: 5, accuracy: High
        $x_5_21 = {85 c0 7c 27 8d 45 d0 6a 08 50 6a 09 ff 75 dc 89 5d d4 ff 15}  //weight: 5, accuracy: High
        $x_5_22 = {85 c0 7c 7a 8d 45 b4 50 68 ff 00 0f 00 8b 4d f0 51 ff 15}  //weight: 5, accuracy: High
        $x_5_23 = {85 c0 7c 30 c7 45 c8 00 00 00 00 6a 08 8d 55 c4 52 6a 09 8b 45 a0 50 ff 15}  //weight: 5, accuracy: High
        $x_5_24 = {85 c0 7c 09 8b 4d b0 c7 01 01 00 00 00 8b 55 c4 52 ff 15}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_2_*))) or
            ((1 of ($x_3_*) and 9 of ($x_2_*))) or
            ((2 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_5_*) and 8 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((2 of ($x_5_*) and 5 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_5_*) and 3 of ($x_2_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*))) or
            ((4 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_HackerDefender_2147680285_4
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/HackerDefender"
        threat_id = "2147680285"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "HackerDefender"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "run as rootkit" ascii //weight: 3
        $x_2_2 = "ZorGLOuBSHELL" ascii //weight: 2
        $x_2_3 = "c:\\hxdlogex.txt" ascii //weight: 2
        $x_1_4 = "\\Device\\\\Udp" ascii //weight: 1
        $x_1_5 = "\\Device\\\\Tcp" ascii //weight: 1
        $x_2_6 = "hxdef-rdrbase-100" ascii //weight: 2
        $x_2_7 = "\\\\.\\HxDefDriver" ascii //weight: 2
        $x_3_8 = "\\\\.\\mailslot\\hxdef-rk100s" ascii //weight: 3
        $x_3_9 = "\\\\.\\mailslot\\hxdef-rk100s0ACEE761" ascii //weight: 3
        $x_2_10 = "\\\\.\\mailslot\\death-ap100s" ascii //weight: 2
        $x_2_11 = "\\\\.\\mailslot\\death-apc" ascii //weight: 2
        $x_2_12 = "\\\\.\\mailslot\\death-apb" ascii //weight: 2
        $x_2_13 = "\\\\.\\mailslot\\death-aps" ascii //weight: 2
        $x_2_14 = "\\\\.\\mailslot\\death-ap100s0ACEE761" ascii //weight: 2
        $x_1_15 = "johndoe221.netfirms.com" ascii //weight: 1
        $x_2_16 = "Prefetch\\*.pf" ascii //weight: 2
        $x_3_17 = "\\\\.\\mailslot\\hxdef-rkc" ascii //weight: 3
        $x_3_18 = "\\\\.\\mailslot\\hxdef-rkb" ascii //weight: 3
        $x_3_19 = "\\\\.\\mailslot\\hxdef-rks" ascii //weight: 3
        $x_1_20 = "uninstalling old service | driver" ascii //weight: 1
        $x_2_21 = "#STEALTH TABLE#" ascii //weight: 2
        $x_2_22 = "#ROOT PROCESSES#" ascii //weight: 2
        $x_2_23 = "#R00T PROCESSES#" ascii //weight: 2
        $x_2_24 = "#STEALTH SERVICES#" ascii //weight: 2
        $x_2_25 = "#STEALTH REGVALUES#" ascii //weight: 2
        $x_2_26 = "#STEALTH REGKEYS#" ascii //weight: 2
        $x_2_27 = "#STEALTH PROCESSES#" ascii //weight: 2
        $x_2_28 = "#STEALTH PORTS#" ascii //weight: 2
        $x_2_29 = "#MASTER PROCESSES#" ascii //weight: 2
        $x_2_30 = "#CONFIGURATION#" ascii //weight: 2
        $x_2_31 = "[COVERS PROCESSES]" ascii //weight: 2
        $x_2_32 = "[COVERS SERVICES]" ascii //weight: 2
        $x_2_33 = "[COVERS REGKEYS]" ascii //weight: 2
        $x_2_34 = "[COVERS REGVALUES]" ascii //weight: 2
        $x_2_35 = "OPENHOLESHELL" ascii //weight: 2
        $x_1_36 = "change service config 2a exists" ascii //weight: 1
        $x_2_37 = "\\\\.\\mailslot\\leighanns" ascii //weight: 2
        $x_2_38 = "\\\\.\\mailslot\\leighannc" ascii //weight: 2
        $x_2_39 = "\\\\.\\mailslot\\leighannb" ascii //weight: 2
        $x_2_40 = "\\\\.\\mailslot\\leighann100s" ascii //weight: 2
        $x_2_41 = "\\\\.\\mailslot\\leighann100sABCDEF" ascii //weight: 2
        $x_2_42 = "[pialia PROCESSES]" ascii //weight: 2
        $x_2_43 = "[pialia SERVICES]" ascii //weight: 2
        $x_2_44 = "[pialia REGKEYS]" ascii //weight: 2
        $x_2_45 = "[pialia REGVALUES]" ascii //weight: 2
        $x_2_46 = "[pialia PORTS]" ascii //weight: 2
        $x_2_47 = "[INVISIBLE TABLE]" ascii //weight: 2
        $x_2_48 = "[INVISIBLE PROCESSES]" ascii //weight: 2
        $x_2_49 = "[INVISIBLE SERVICES]" ascii //weight: 2
        $x_2_50 = "[INVISIBLE REGKEYS]" ascii //weight: 2
        $x_2_51 = "[INVISIBLE REGVALUES]" ascii //weight: 2
        $x_2_52 = "[INVISIBLE PORTS]" ascii //weight: 2
        $x_2_53 = "[HIDDEN PROCESSES]" ascii //weight: 2
        $x_2_54 = "[ROOT PROCESSES]" ascii //weight: 2
        $x_2_55 = "[HIDDEN SERVICES]" ascii //weight: 2
        $x_2_56 = "[HIDDEN REGKEYS]" ascii //weight: 2
        $x_2_57 = "[HIDDEN REGVALUES]" ascii //weight: 2
        $x_1_58 = "BACKDOORSHELL" ascii //weight: 1
        $x_1_59 = "SERVICEDISPLAYNAME" ascii //weight: 1
        $x_1_60 = "SERVICEDESCRIPTION" ascii //weight: 1
        $x_1_61 = "FILEMAPPINGNAME" ascii //weight: 1
        $x_1_62 = "SVCDISPLAYNAME" ascii //weight: 1
        $x_1_63 = "SVCDESCRIPTION" ascii //weight: 1
        $x_1_64 = "DRVFILENAME" ascii //weight: 1
        $x_5_65 = "Hacker Defender 1.0.0 Redir Base" ascii //weight: 5
        $x_1_66 = "Hiding console" ascii //weight: 1
        $x_3_67 = "Corrupted inifile! Delete it or fix it and restart this application" ascii //weight: 3
        $x_3_68 = "-:bd:-" ascii //weight: 3
        $x_3_69 = "-:INSTALLONLY" ascii //weight: 3
        $x_3_70 = "-:REFRESH" ascii //weight: 3
        $x_3_71 = "-:NOSERVICE" ascii //weight: 3
        $x_3_72 = "-:UNINSTALL" ascii //weight: 3
        $x_3_73 = "-:BD:-" ascii //weight: 3
        $x_2_74 = "__INSTALL" ascii //weight: 2
        $x_2_75 = "__RELOAD" ascii //weight: 2
        $x_2_76 = "__STEALTH" ascii //weight: 2
        $x_2_77 = "__DIE" ascii //weight: 2
        $x_2_78 = "GHandles v1.0 for GKit by gray,thx for Holy_Father && Ratter/29A" ascii //weight: 2
        $x_2_79 = "\\\\.\\mailslot\\media-black" ascii //weight: 2
        $x_3_80 = "\\\\.\\mailslot\\media-ckr" ascii //weight: 3
        $x_3_81 = "\\\\.\\mailslot\\media-rkb" ascii //weight: 3
        $x_3_82 = "\\\\.\\mailslot\\media-rks" ascii //weight: 3
        $x_3_83 = "\\\\.\\mailslot\\media-black0ACEE761" ascii //weight: 3
        $x_2_84 = "\\\\.\\mailslot\\myapp-nts" ascii //weight: 2
        $x_2_85 = "--JUST_INSTALL" ascii //weight: 2
        $x_2_86 = "--REPLAY" ascii //weight: 2
        $x_2_87 = "--BE_COOL" ascii //weight: 2
        $x_2_88 = "--REMOVE_ME" ascii //weight: 2
        $x_2_89 = "--NT--" ascii //weight: 2
        $x_2_90 = "=!=%=)=-=1=5=9===A=E=I=M=Q=U=Y=]=a=e=i=m=q=u=y=}=" ascii //weight: 2
        $x_1_91 = "CreateMailSlot" ascii //weight: 1
        $x_2_92 = "\\\\.\\mailslot\\tufhk-nt100s0ACEE761" ascii //weight: 2
        $x_2_93 = "\\\\.\\mailslot\\tufhk-nt100s" ascii //weight: 2
        $x_2_94 = "\\\\.\\mailslot\\tufhk-ntc" ascii //weight: 2
        $x_2_95 = "\\\\.\\mailslot\\tufhk-ntb" ascii //weight: 2
        $x_2_96 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c ?? ?? ?? ?? ?? 2d 72 6b 73}  //weight: 2, accuracy: Low
        $x_2_97 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c ?? ?? ?? ?? ?? 2d 72 6b 62}  //weight: 2, accuracy: Low
        $x_2_98 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c ?? ?? ?? ?? ?? 2d 72 6b 63}  //weight: 2, accuracy: Low
        $x_2_99 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c ?? ?? ?? ?? ?? 2d 72 6b 31 30 30 73}  //weight: 2, accuracy: Low
        $x_2_100 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c ?? ?? ?? ?? ?? ?? ?? ?? 31 30 30 73}  //weight: 2, accuracy: Low
        $x_2_101 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c [0-6] 2d 78 64 62}  //weight: 2, accuracy: Low
        $x_2_102 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c [0-6] 2d 78 64 63}  //weight: 2, accuracy: Low
        $x_2_103 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c [0-6] 2d 78 64 31 33 30 73}  //weight: 2, accuracy: Low
        $x_2_104 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c [0-6] 2d 78 64 31 33 30 73 41 42 43 44}  //weight: 2, accuracy: Low
        $x_2_105 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c [0-6] 62 63 62}  //weight: 2, accuracy: Low
        $x_2_106 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c [0-6] 62 63 63}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 14 of ($x_1_*))) or
            ((3 of ($x_2_*) and 12 of ($x_1_*))) or
            ((4 of ($x_2_*) and 10 of ($x_1_*))) or
            ((5 of ($x_2_*) and 8 of ($x_1_*))) or
            ((6 of ($x_2_*) and 6 of ($x_1_*))) or
            ((7 of ($x_2_*) and 4 of ($x_1_*))) or
            ((8 of ($x_2_*) and 2 of ($x_1_*))) or
            ((9 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 8 of ($x_2_*))) or
            ((2 of ($x_3_*) and 12 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 6 of ($x_2_*))) or
            ((3 of ($x_3_*) and 9 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 5 of ($x_2_*))) or
            ((4 of ($x_3_*) and 6 of ($x_1_*))) or
            ((4 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_3_*) and 3 of ($x_2_*))) or
            ((5 of ($x_3_*) and 3 of ($x_1_*))) or
            ((5 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_3_*) and 2 of ($x_2_*))) or
            ((6 of ($x_3_*))) or
            ((1 of ($x_5_*) and 13 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 6 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 7 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 10 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 5 of ($x_3_*))) or
            (all of ($x*))
        )
}

