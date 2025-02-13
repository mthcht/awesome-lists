rule Trojan_Win32_Autorun_2147604792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autorun"
        threat_id = "2147604792"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\vidc20.exe" wide //weight: 3
        $x_2_2 = "\\Files\\final.exe" wide //weight: 2
        $x_1_3 = "shell\\open\\Command=install.exe" wide //weight: 1
        $x_1_4 = "shell\\explore\\Command=install.exe" wide //weight: 1
        $x_3_5 = {33 00 32 00 00 00 00 00 1a 00 00 00 3a 00 5c 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00 1a 00 00 00 3a 00 5c 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 00 00 12 00 00 00 5b 00 41 00 75 00 74 00 6f 00 52 00 75 00 6e 00 5d 00 00 00 04 00 00 00 01 00 88 00 20 00 00 00 6f 00 70 00 65 00 6e 00 3d 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 65 00 78 00 65}  //weight: 3, accuracy: High
        $x_3_6 = {00 75 00 6e 00 00 00 10 00 00 00 77 00 69 00 6e 00 31 00 6f 00 67 00 69 00 6e 00 00 00 00 00 12 00 00 00 77 00 69 00 6e 00 32 00 6c 00 6f 00 67 00 69 00 6e 00 00}  //weight: 3, accuracy: High
        $x_2_7 = "derStyoffice" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Autorun_M_2147726569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autorun.M!bit"
        threat_id = "2147726569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /im" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "SELECT * FROM Win32_OperatingSystem" ascii //weight: 1
        $x_1_4 = "SELECT origin_url, username_value, password_value FROM logins" ascii //weight: 1
        $x_1_5 = "Bitcoin\\wallet.dat" ascii //weight: 1
        $x_1_6 = "screenshot.bmp" ascii //weight: 1
        $x_1_7 = "ipconfig >ipconfig.txt" ascii //weight: 1
        $x_1_8 = "Local Settings\\Application Data\\Yandex\\YandexBrowser\\User Data" wide //weight: 1
        $x_1_9 = "Local Settings\\Application Data\\Google\\Chrome\\User Data" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Autorun_PA_2147745482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autorun.PA!MTB"
        threat_id = "2147745482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Vmaker - New Screenshot -" wide //weight: 1
        $x_1_2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" wide //weight: 1
        $x_1_3 = "Hidden" wide //weight: 1
        $x_1_4 = "autorun.inf" wide //weight: 1
        $x_1_5 = "shellexecute=" wide //weight: 1
        $x_1_6 = "REG add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableTaskMgr /t REG_DWORD /d 0" wide //weight: 1
        $x_1_7 = "REG add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableRegistryTools /t REG_DWORD /d 1" wide //weight: 1
        $x_1_8 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_9 = "keyscrambler" wide //weight: 1
        $x_1_10 = "New Keys" wide //weight: 1
        $x_1_11 = "smtp.gmail.com" wide //weight: 1
        $x_1_12 = "typewriter" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

