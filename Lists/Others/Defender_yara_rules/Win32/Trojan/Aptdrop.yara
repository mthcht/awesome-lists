rule Trojan_Win32_Aptdrop_A_2147729585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Aptdrop.A"
        threat_id = "2147729585"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Aptdrop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":\\Users\\Naughty Develop\\Desktop\\New Backdoor2.5-with-cmd-resource\\New Backdoor2.3\\Release\\Backdoor.pdb" ascii //weight: 1
        $x_1_2 = ":\\FirstBackDoor(2015_1_10)\\FirstBackDoor(2015_1_10)\\Release\\FirstUrlMon.pdb" ascii //weight: 1
        $x_1_3 = ":\\PH2015_2.2\\New Backdoor2.2\\New Backdoor2.2\\Release\\CppUACSelfElevation.pdb" ascii //weight: 1
        $x_1_4 = ":\\work\\4th\\plugin\\OffSM\\Release\\OffSM.pdb" ascii //weight: 1
        $x_1_5 = ":\\work\\4th\\plugin\\SM\\Release\\SM.pdb" ascii //weight: 1
        $x_1_6 = ":\\work\\n1st\\Agent\\Release\\HncUp.pdb" ascii //weight: 1
        $x_1_7 = ":\\work\\n1st\\Agent\\Release\\PotPlayerUpdate.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Aptdrop_B_2147729586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Aptdrop.B"
        threat_id = "2147729586"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Aptdrop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_50_1 = ":\\TASK\\ProgamsByMe(2015.1" ascii //weight: 50
        $x_1_2 = "\\2010Main\\EXE_AND_SERVICE\\Release\\Manager.pdb" ascii //weight: 1
        $x_1_3 = "\\FirstBackDoor(2015_7_24)\\Release\\office.pdb" ascii //weight: 1
        $x_1_4 = "\\FirstBackdoor(2015_7_24)\\Release\\PrivilegeEscalation.pdb" ascii //weight: 1
        $x_1_5 = "\\Happy\\2010PHV2\\EXE_AND_SERVICE\\Release\\KeyLogger.pdb" ascii //weight: 1
        $x_1_6 = "\\Happy\\2010PHV2\\EXE_AND_SERVICE\\Release\\ScreenCap.pdb" ascii //weight: 1
        $x_1_7 = "\\HncUpdateUAC\\C++\\Release\\CppUACSelfElevation.pdb" ascii //weight: 1
        $x_1_8 = "\\HncUpdateUAC\\C++\\Release\\Installer.pdb" ascii //weight: 1
        $x_1_9 = "\\HncUpdateUAC\\C++\\Release\\Manager_Them.pdb" ascii //weight: 1
        $x_1_10 = "\\MyWork\\Relative Backdoor\\KeyLogger_ScreenCap_Manager\\Release\\SoundRec.pdb" ascii //weight: 1
        $x_1_11 = "\\MyWork\\Relative Backdoor\\KeyLogger_ScreenCap_Manager\\Release\\Manger.pdb" ascii //weight: 1
        $x_1_12 = "\\MyWork\\Relative Backdoor\\KeyLogger_ScreenCap_Manager\\Release\\ScreenCap.pdb" ascii //weight: 1
        $x_1_13 = "\\ShellCode\\Debug\\HwpConvert.pdb" ascii //weight: 1
        $x_1_14 = "\\ShellCode\\Release\\UACTest.pdb" ascii //weight: 1
        $x_1_15 = "\\EXE_AND_SERVICE\\EXE_AND_SERVICE\\Debug\\Manager.pdb" ascii //weight: 1
        $x_1_16 = "\\EXE_AND_SERVICE\\EXE_AND_SERVICE\\Release\\TransProxy.pdb" ascii //weight: 1
        $x_1_17 = "\\MyWork\\Relative Backdoor\\Installer\\Release\\Installer.pdb" ascii //weight: 1
        $x_1_18 = "\\MyWork\\Relative Backdoor\\New Backdoor2.4\\Release\\InstallBD.pdb" ascii //weight: 1
        $x_1_19 = "\\MyWork\\Relative Backdoor\\New Backdoor2.3\\Release\\InstallBD.pdb" ascii //weight: 1
        $x_1_20 = "\\MyWork\\Relative Backdoor\\New Backdoor2.3-with-cmd-resource\\New Backdoor2.3\\Release\\Backdoor.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Aptdrop_E_2147730438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Aptdrop.E"
        threat_id = "2147730438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Aptdrop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PEConsole\\Backend\\Release\\payload.pdb" ascii //weight: 1
        $x_1_2 = "ws://45.32.117.116:443PAdefaultPhttp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Aptdrop_F_2147730628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Aptdrop.F"
        threat_id = "2147730628"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Aptdrop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 b9 40 9c 00 00 8b c5 05 01 01 01 01 51 8a c8 d3 c0 59 51 8a c8 d3 c0 59 05 01 01 01 00 05 01 01 01 01 8b e8 e2 df 59 8b dd ac 32 c3 aa e2 d0}  //weight: 1, accuracy: High
        $x_1_2 = "Good night for a walk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Aptdrop_G_2147730630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Aptdrop.G"
        threat_id = "2147730630"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Aptdrop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 00 63 00 20 00 70 00 69 00 6e 00 67 00 20 00 31 00 2e 00 31 00 2e 00 31 00 2e 00 31 00 20 00 2d 00 6e 00 20 00 33 00 20 00 26 00 20 00 64 00 65 00 6c 00 20 00 25 00 73 00 00 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00 6f 00 70 00 65 00 6e 00 00 00 00 00 44 00 46 00 54 00 30 00 32 00 34 00 38 00 30 00 33 00 39 00 38 00 34 00 30 00 32 00 39 00 33 00 2e 00 74 00 6d 00 70 00 00 00 00 00 5c 00 77 00 69 00 6e 00 75 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Aptdrop_R_2147730787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Aptdrop.R"
        threat_id = "2147730787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Aptdrop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cf 8b c7 c1 e9 05 03 4c 24 ?? c1 e0 04 03 44 24 ?? 33 c8 8d 04 2f 33 c8 8b 44 24 ?? 2b d9 6a f7 59 2b c8 03 e9 4e 75 ?? 8b 74 24 24 89 7e 04 5f 89 1e 5e 5d 5b 83 c4 ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Aptdrop_RU_2147730827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Aptdrop.RU"
        threat_id = "2147730827"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Aptdrop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 ff 33 58 83 c3 04 f7 d8 f8 83 d8 26 8d 40 ff 29 f8 8d 38 [0-8] f8 83 d9 fc 8d 52 04 81 fa 88 06 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {51 ff 33 58 83 c3 04 f7 d8 83 e8 26 83 e8 02 83 e8 ff 29 f8 50 5f c7 01 00 00 00 00 01 01 83 e9 fc 83 c2 04 81 fa 88 06 00 00 75 d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Aptdrop_L_2147735622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Aptdrop.L"
        threat_id = "2147735622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Aptdrop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\aa\\Documents\\Visual Studio 2015\\Projects\\agent k nov\\Release\\agent k nov.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Aptdrop_H_2147735887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Aptdrop.H"
        threat_id = "2147735887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Aptdrop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ping 127.0.0.1 -459B2-3311-54C3- Processid:{0A10 /Processid:{712C245-2190-7215-A3C5-43215926716Asoftware\\Intel\\Jicacls \"%s\" /graft\\windows\\curreNtQueryInformatiIntelGraphicsConsoftware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Aptdrop_N_2147739795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Aptdrop.N"
        threat_id = "2147739795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Aptdrop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "N:\\C#MM\\YKMM\\LoadW\\obj\\Release\\LoadW.pdb" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

