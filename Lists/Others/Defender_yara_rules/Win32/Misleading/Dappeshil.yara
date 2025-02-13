rule Misleading_Win32_Dappeshil_240851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/Dappeshil"
        threat_id = "240851"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "Dappeshil"
        severity = "30"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PrivacyMaster\\bin\\Release\\PCPrivacyShield.pdb" ascii //weight: 1
        $x_1_2 = "get_IeUserPassScanner" ascii //weight: 1
        $x_1_3 = "PCPrivacyShield.exe" ascii //weight: 1
        $x_1_4 = {53 68 69 65 6c 64 41 70 70 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Misleading_Win32_Dappeshil_240851_1
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/Dappeshil"
        threat_id = "240851"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "Dappeshil"
        severity = "30"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RegCleaner\\bin\\Release\\PCCleaningUtility.pdb" ascii //weight: 1
        $x_1_2 = "PCCleaningUtility.exe" ascii //weight: 1
        $x_1_3 = "get_FiftyFixed" ascii //weight: 1
        $x_1_4 = "IeSavedPasswordScanner" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Misleading_Win32_Dappeshil_240851_2
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/Dappeshil"
        threat_id = "240851"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "Dappeshil"
        severity = "30"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RegCleaner\\bin\\Release\\PCRegistryShield.pdb" ascii //weight: 1
        $x_1_2 = "RegCleaner.Startup.resources" ascii //weight: 1
        $x_1_3 = "PCRegistryShield.exe" ascii //weight: 1
        $x_1_4 = {53 68 69 65 6c 64 41 70 70 73 00}  //weight: 1, accuracy: High
        $x_1_5 = "get_FiftyFixed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Misleading_Win32_Dappeshil_240851_3
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/Dappeshil"
        threat_id = "240851"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "Dappeshil"
        severity = "30"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Welcome to the PC Cleaning Utility Wizard" ascii //weight: 1
        $x_1_2 = "http://shieldapps.com/eula/" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\PC Cleaning Utility" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\PC Cleaning Utility" ascii //weight: 1
        $x_1_5 = "CreateMutex(i 0, i 0, t \"PCCleaningUtilitySetup.exe\")" ascii //weight: 1
        $x_1_6 = "labelname=PC Cleaning Utility&appver=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Misleading_Win32_Dappeshil_240851_4
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/Dappeshil"
        threat_id = "240851"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "Dappeshil"
        severity = "30"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Welcome to the PC Privacy Shield Wizard" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\PC Privacy Shield" ascii //weight: 1
        $x_1_3 = "CreateMutex(i 0, i 0, t \"PCPrivacyShieldSetup.exe\")" ascii //weight: 1
        $x_1_4 = "labelname=PC Privacy Shield&appver=" ascii //weight: 1
        $x_1_5 = "\\PCPrivacyShield.exe\" startscan" ascii //weight: 1
        $x_1_6 = "http://shieldapps.com/eula/" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\ShieldApps\\PC Privacy Shield" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Misleading_Win32_Dappeshil_240851_5
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/Dappeshil"
        threat_id = "240851"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "Dappeshil"
        severity = "30"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Welcome to the PC Registry Shield Wizard" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\PC Registry Shield" ascii //weight: 1
        $x_1_3 = "CreateMutex(i 0, i 0, t \"PCRegistryShieldSetup.exe\"" ascii //weight: 1
        $x_1_4 = "labelname=PC Registry Shield&appver=" ascii //weight: 1
        $x_1_5 = "\\PCRegistryShield.exe\" startscan" ascii //weight: 1
        $x_1_6 = "http://shieldapps.com/eula/" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\ShieldApps\\PC Registry Shield" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

