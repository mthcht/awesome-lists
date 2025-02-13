rule Backdoor_Win32_Hackdef_A_2147792329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hackdef.gen!A"
        threat_id = "2147792329"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hackdef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
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
        $x_3_68 = "-:INSTALLONLY" ascii //weight: 3
        $x_3_69 = "-:REFRESH" ascii //weight: 3
        $x_3_70 = "-:NOSERVICE" ascii //weight: 3
        $x_3_71 = "-:UNINSTALL" ascii //weight: 3
        $x_2_72 = "__INSTALL" ascii //weight: 2
        $x_2_73 = "__RELOAD" ascii //weight: 2
        $x_2_74 = "__STEALTH" ascii //weight: 2
        $x_2_75 = "__DIE" ascii //weight: 2
        $x_2_76 = "GHandles v1.0 for GKit by gray,thx for Holy_Father && Ratter/29A" ascii //weight: 2
        $x_3_77 = "\\\\.\\mailslot\\media-ckr" ascii //weight: 3
        $x_3_78 = "\\\\.\\mailslot\\media-rkb" ascii //weight: 3
        $x_3_79 = "\\\\.\\mailslot\\media-rks" ascii //weight: 3
        $x_3_80 = "\\\\.\\mailslot\\media-black0ACEE761" ascii //weight: 3
        $x_2_81 = "\\\\.\\mailslot\\media-black" ascii //weight: 2
        $x_2_82 = "\\\\.\\mailslot\\myapp-nts" ascii //weight: 2
        $x_2_83 = "--JUST_INSTALL" ascii //weight: 2
        $x_2_84 = "--REPLAY" ascii //weight: 2
        $x_2_85 = "--BE_COOL" ascii //weight: 2
        $x_2_86 = "--REMOVE_ME" ascii //weight: 2
        $x_2_87 = "--NT--" ascii //weight: 2
        $x_2_88 = "=!=%=)=-=1=5=9===A=E=I=M=Q=U=Y=]=a=e=i=m=q=u=y=}=" ascii //weight: 2
        $x_1_89 = "CreateMailSlot" ascii //weight: 1
        $x_2_90 = "\\\\.\\mailslot\\tufhk-nt100s0ACEE761" ascii //weight: 2
        $x_2_91 = "\\\\.\\mailslot\\tufhk-nt100s" ascii //weight: 2
        $x_2_92 = "\\\\.\\mailslot\\tufhk-ntc" ascii //weight: 2
        $x_2_93 = "\\\\.\\mailslot\\tufhk-ntb" ascii //weight: 2
        $x_3_94 = "-:bd:-" ascii //weight: 3
        $x_2_95 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c ?? ?? ?? ?? ?? 2d 72 6b 73}  //weight: 2, accuracy: Low
        $x_2_96 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c ?? ?? ?? ?? ?? 2d 72 6b 62}  //weight: 2, accuracy: Low
        $x_2_97 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c ?? ?? ?? ?? ?? 2d 72 6b 63}  //weight: 2, accuracy: Low
        $x_2_98 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c ?? ?? ?? ?? ?? 2d 72 6b 31 30 30 73}  //weight: 2, accuracy: Low
        $x_2_99 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c ?? ?? ?? ?? ?? ?? ?? ?? 31 30 30 73}  //weight: 2, accuracy: Low
        $x_2_100 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c [0-6] 2d 78 64 62}  //weight: 2, accuracy: Low
        $x_2_101 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c [0-6] 2d 78 64 63}  //weight: 2, accuracy: Low
        $x_2_102 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c [0-6] 2d 78 64 31 33 30 73}  //weight: 2, accuracy: Low
        $x_2_103 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c [0-6] 2d 78 64 31 33 30 73 41 42 43 44}  //weight: 2, accuracy: Low
        $x_2_104 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c [0-6] 62 63 62}  //weight: 2, accuracy: Low
        $x_2_105 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c [0-6] 62 63 63}  //weight: 2, accuracy: Low
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

rule Backdoor_Win32_Hackdef_C_2147792432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hackdef.gen!C"
        threat_id = "2147792432"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hackdef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\\\.\\Mailslot\\crss-xd130s" ascii //weight: 2
        $x_2_2 = "\\\\.\\Mailslot\\crss-xdc" ascii //weight: 2
        $x_2_3 = "\\\\.\\Mailslot\\crss-xdb" ascii //weight: 2
        $x_2_4 = "\\\\.\\crssDriver" ascii //weight: 2
        $x_3_5 = "-:bd:-" ascii //weight: 3
        $x_3_6 = "-install" ascii //weight: 3
        $x_3_7 = "-refresh" ascii //weight: 3
        $x_3_8 = "-start" ascii //weight: 3
        $x_3_9 = "-uninstall" ascii //weight: 3
        $x_3_10 = "-backdoor:-" ascii //weight: 3
        $x_2_11 = "OpenServiceA" ascii //weight: 2
        $x_2_12 = "OpenSCManagerA" ascii //weight: 2
        $x_2_13 = "LockServiceDatabase" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_3_*) and 6 of ($x_2_*))) or
            ((5 of ($x_3_*) and 5 of ($x_2_*))) or
            ((6 of ($x_3_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Hackdef_AR_2147792475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hackdef.AR!MTB"
        threat_id = "2147792475"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hackdef"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "login detected, begin hijacking\"" ascii //weight: 1
        $x_1_2 = "\"profiles hijacked!\"" ascii //weight: 1
        $x_1_3 = "\\shadowcopy.exe" ascii //weight: 1
        $x_1_4 = "sethijack" ascii //weight: 1
        $x_1_5 = {73 00 75 00 63 00 63 00 65 00 73 00 73 00 20 00 66 00 69 00 72 00 65 00 66 00 6f 00 78 00 20 00 70 00 72 00 6f 00 66 00 [0-8] 20 00 63 00 6f 00 70 00 79 00}  //weight: 1, accuracy: Low
        $x_1_6 = {73 75 63 63 65 73 73 20 66 69 72 65 66 6f 78 20 70 72 6f 66 [0-8] 20 63 6f 70 79}  //weight: 1, accuracy: Low
        $x_1_7 = {73 00 75 00 63 00 63 00 65 00 73 00 73 00 20 00 63 00 68 00 72 00 6f 00 6d 00 65 00 20 00 70 00 72 00 6f 00 66 00 [0-8] 20 00 63 00 6f 00 70 00 79 00}  //weight: 1, accuracy: Low
        $x_1_8 = {73 75 63 63 65 73 73 20 63 68 72 6f 6d 65 20 70 72 6f 66 [0-8] 20 63 6f 70 79}  //weight: 1, accuracy: Low
        $x_1_9 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-63] 2f 00 [0-20] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_10 = {68 74 74 70 73 3a 2f 2f [0-63] 2f [0-20] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_11 = "*.*\"" ascii //weight: 1
        $x_1_12 = "/s /i /y /r" ascii //weight: 1
        $x_1_13 = "selfkill" ascii //weight: 1
        $x_1_14 = "cmd.exe /C taskkill /F /IM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule Backdoor_Win32_Hackdef_AV_2147792476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hackdef.AV!MTB"
        threat_id = "2147792476"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hackdef"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "systemroot" ascii //weight: 1
        $x_1_2 = "selfkill" ascii //weight: 1
        $x_1_3 = "killalltuns" ascii //weight: 1
        $x_1_4 = "\\libcrypto.dll" ascii //weight: 1
        $x_1_5 = "/c ping localhost -n 30 > nul & del" ascii //weight: 1
        $x_1_6 = "xcopy" ascii //weight: 1
        $x_1_7 = {41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 [0-8] 2f 00 59 00 20 00 2f 00 48 00 20 00 2f 00 45 00 20 00 2f 00 65 00 78 00 63 00 6c 00 75 00 64 00 65 00 3a 00 25 00 74 00 65 00 6d 00 70 00 25 00 5c 00 [0-8] 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
        $x_1_8 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 [0-8] 2f 59 20 2f 48 20 2f 45 20 2f 65 78 63 6c 75 64 65 3a 25 74 65 6d 70 25 5c [0-8] 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_9 = {41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 72 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 5c 00 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 5c 00 46 00 69 00 72 00 65 00 66 00 6f 00 78 00 5c 00 50 00 72 00 6f 00 66 00 69 00 6c 00 65 00 73 00 [0-8] 2f 00 59 00 20 00 2f 00 48 00 20 00 2f 00 45 00 20 00 2f 00 65 00 78 00 63 00 6c 00 75 00 64 00 65 00 3a 00 25 00 74 00 65 00 6d 00 70 00 25 00 5c 00 [0-8] 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
        $x_1_10 = {41 70 70 44 61 74 61 5c 72 6f 61 6d 69 6e 67 5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 50 72 6f 66 69 6c 65 73 [0-8] 2f 59 20 2f 48 20 2f 45 20 2f 65 78 63 6c 75 64 65 3a 25 74 65 6d 70 25 5c [0-8] 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_11 = "parent.lock" ascii //weight: 1
        $x_1_12 = "URLDownloadToFileW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

