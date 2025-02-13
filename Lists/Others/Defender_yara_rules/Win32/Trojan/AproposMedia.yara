rule Trojan_Win32_AproposMedia_14978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AproposMedia"
        threat_id = "14978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AproposMedia"
        severity = "31"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 69 6e 47 65 6e 65 72 69 63 73 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = "Logging@WinGenerics" ascii //weight: 1
        $x_1_3 = "WindowsHooksStorage:" ascii //weight: 1
        $x_1_4 = "InternetCrackUrl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AproposMedia_14978_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AproposMedia"
        threat_id = "14978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AproposMedia"
        severity = "31"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "AproposClientUnInstallerIsRunning" ascii //weight: 3
        $x_3_2 = "AproposClientTerminate" ascii //weight: 3
        $x_2_3 = "Software\\Apropos\\Client" ascii //weight: 2
        $x_3_4 = "AproposUninst.ini" ascii //weight: 3
        $x_1_5 = "adchannel.a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AproposMedia_14978_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AproposMedia"
        threat_id = "14978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AproposMedia"
        severity = "31"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "AproposClientUnInstallerIsRunning" ascii //weight: 3
        $x_3_2 = "AproposClientTerminate" ascii //weight: 3
        $x_2_3 = "Software\\AdMedia\\Client" ascii //weight: 2
        $x_2_4 = "AdMediaUninst.ini" ascii //weight: 2
        $x_3_5 = "AproposObserver::" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AproposMedia_14978_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AproposMedia"
        threat_id = "14978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AproposMedia"
        severity = "31"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Winhelper::Registry::read_string: RegQueryValueEx failed. Last error = 0x" ascii //weight: 1
        $x_3_2 = "http://66.98.138.92/PH/" ascii //weight: 3
        $x_2_3 = "SOFTWARE\\Apropos\\Client" ascii //weight: 2
        $x_1_4 = "/status" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AproposMedia_14978_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AproposMedia"
        threat_id = "14978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AproposMedia"
        severity = "31"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "@Window@Win32@GUI@WinGenerics@@SA" ascii //weight: 2
        $x_1_2 = "WinGenerics.dll" ascii //weight: 1
        $x_3_3 = "AdChannelResponse::" ascii //weight: 3
        $x_3_4 = "AdContainerWindow::" ascii //weight: 3
        $x_3_5 = "{8856F961-340A-11D0-A96B-00C04FD705A2}" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AproposMedia_14978_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AproposMedia"
        threat_id = "14978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AproposMedia"
        severity = "31"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PartnerId" ascii //weight: 1
        $x_3_2 = "CtxPls" ascii //weight: 3
        $x_1_3 = "InstallationId" ascii //weight: 1
        $x_3_4 = "download.contextplus.net" ascii //weight: 3
        $x_3_5 = "adchannel.contextplus.net" ascii //weight: 3
        $x_3_6 = "/apropos/client/LDV_<<version>>" ascii //weight: 3
        $x_3_7 = "/shared/Msvcp60Installer.exe" ascii //weight: 3
        $x_3_8 = "/services/AUServer" ascii //weight: 3
        $x_3_9 = "CtxPlus" ascii //weight: 3
        $x_1_10 = "HookDll.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_3_*) and 3 of ($x_1_*))) or
            ((6 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AproposMedia_14978_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AproposMedia"
        threat_id = "14978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AproposMedia"
        severity = "31"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "LoaderSessionIsStarted" ascii //weight: 3
        $x_5_2 = "http://download.contextplus.net/shared/Msvcp60Installer.exe" ascii //weight: 5
        $x_1_3 = "Software\\AutoLoader" ascii //weight: 1
        $x_1_4 = "AutoLoaderSession" ascii //weight: 1
        $x_1_5 = "AutoUpdaterInstaller.exe" ascii //weight: 1
        $x_1_6 = "adchannel.contextplus.net" ascii //weight: 1
        $x_3_7 = "AproposClientInstaller" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AproposMedia_14978_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AproposMedia"
        threat_id = "14978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AproposMedia"
        severity = "31"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {53 52 51 57 8b da 03 52 3c 8b 7a 78 03 fb 57 ff 72 7c 8b f0 8b c8 4e c1 e9 10 e3 37 8b 4f 18 8b 77 20 03 f3 92 ad 56 8d 34 18 38 56 02 75 07 51 33 c9 ff d5 04 59 5e 3b c2 74 09 e2 e8 5f 5f 91 8b f0 eb 27 2b f3 2b 77 20 d1 ee 03 77 24 0f b7 74 1e fe c1 e6 02 03 77 1c 03 f3 ad 03 c3 59 5f 2b f8 77 07 03 f9 77 03 33 f6 96 5f 59 5a 5b c3}  //weight: 2, accuracy: High
        $x_2_2 = {60 ff 74 24 30 ff 74 24 30 ff 74 24 30 ff d5 11 33 c0 89 45 36 89 45 62 89 45 66 b0 e0 ff d5 02 92 8d 7a 2b 89 6a 2f ff d5 0b 8b 7d 3a 8b 55 52 33 c9 b0 f0 ff d5 02 96 b1 06 ad 56 ff d5 03 80 f9 03 77 08 51 33 c9 ff d5 07 91 59 ff d5 0c 5e e2 e8 61 33 c0 c3}  //weight: 2, accuracy: High
        $x_2_3 = {53 4d 41 20 4d 2e 38 20 43 6f 72 65 2e 20 62 79 20 5a 75 66 79 78 65 00 46 00 69 00 6c 00 65 00 00 00 44 00 65 00 62 00 67 00 00 00 4b 00 65 00 79 00 73 00 00 00 41 00 75 00 74 00 6f 00 00 00 45 6e 75 6d 5c 52 6f 6f 74 5c 4c 45 47 41 43 59 5f 5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 00 00 73 00 5c 00 00 00 4b 00 45 00 52 00 4e 00 45 00 4c 00 33 00 32 00 77 00 69 00 6e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

