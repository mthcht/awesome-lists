rule Trojan_Win32_Radonskra_A_2147690952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Radonskra.A"
        threat_id = "2147690952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Radonskra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/delete /tn SystemScript /f" ascii //weight: 1
        $x_1_2 = "/create /tn SystemScript /tr \"DWVALUE\" /sc ONLOGON /f" ascii //weight: 1
        $x_1_3 = "pop.okinofilm.ru/ru.php?snid=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Radonskra_A_2147690952_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Radonskra.A"
        threat_id = "2147690952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Radonskra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d.location.protocol=='https:')exit;ourdom='http:" ascii //weight: 1
        $x_1_2 = "\\Microsoft\\Windows\\system.exe" ascii //weight: 1
        $x_1_3 = "/create /tn SystemScript /tr \"DWVALUE\" /sc ONLOGON /f" ascii //weight: 1
        $x_1_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 63 72 69 70 74 53 79 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Radonskra_B_2147692460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Radonskra.B"
        threat_id = "2147692460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Radonskra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/create /tn SystemScript /tr \"DWVALUE\" /sc ONLOGON /f" ascii //weight: 1
        $x_1_2 = "software\\microsoft\\windows\\currentversion\\run" ascii //weight: 1
        $x_1_3 = "DQovLyBAaW5jbHVkZSBodHRwczovLyoNCi8vID09L1VzZXJTY3JpcHQ9PQ0KDQo=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Radonskra_C_2147692619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Radonskra.C"
        threat_id = "2147692619"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Radonskra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Microsoft\\Windows\\windows.zpx" ascii //weight: 1
        $x_1_2 = "\"safebrowsing\":{\"enabled\":false}" ascii //weight: 1
        $x_1_3 = "\"homepageURL\":\"http://www.greasespot.net/\"" ascii //weight: 1
        $x_1_4 = "/create /tn SystemScript /tr \"DWVALUE\" /sc ONLOGON /f" ascii //weight: 1
        $x_1_5 = "Ly8gPT1Vc2VyU2NyaXB0PT0NCi8vIEBpbmNsdWRlIGh0dHA6Ly8qDQovLyBAaW5jbHVkZSBodHRwczovLyoNCi8vID09L1VzZXJTY3JpcHQ9PQ0KDQ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Radonskra_D_2147692742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Radonskra.D"
        threat_id = "2147692742"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Radonskra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 63 72 65 61 74 65 20 2f 74 6e [0-16] 2f 74 72 20 22 44 57 56 41 4c 55 45 22 20 2f 73 63 20 4f 4e 4c 4f 47 4f 4e 20 2f 66}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 3a 2f 2f [0-16] 2e 72 75 2f [0-16] 2e 70 68 70 3f 73 6e 69 64 3d}  //weight: 1, accuracy: Low
        $x_1_3 = "d.location.protocol=='https:')exit;ourdom='HTTP'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Radonskra_E_2147693616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Radonskra.E"
        threat_id = "2147693616"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Radonskra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 7d fc 20 76 ?? 80 7d fc 2c 75 ?? e9 8c 00 00 00 80 7d fc 7d 75}  //weight: 1, accuracy: Low
        $x_1_2 = "\\\\.\\PhysicalDrive0" ascii //weight: 1
        $x_1_3 = "\"safebrowsing\":{\"enabled\":false}," ascii //weight: 1
        $x_1_4 = {53 79 73 74 65 6d 53 63 72 69 70 74 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Radonskra_F_2147694119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Radonskra.F"
        threat_id = "2147694119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Radonskra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/create /tn SystemScript /tr \"DWVALUE\" /sc ONLOGON /f" ascii //weight: 2
        $x_1_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 63 72 69 70 74 53 79 73 00}  //weight: 1, accuracy: High
        $x_1_3 = "/delete /tn SystemScript /f" ascii //weight: 1
        $x_1_4 = "windows.zpx" ascii //weight: 1
        $x_1_5 = "dows.zpz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Radonskra_G_2147718012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Radonskra.G!bit"
        threat_id = "2147718012"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Radonskra"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 68 72 6f 6d 65 2e 65 78 65 00 00 66 69 72 65 66 6f 78 2e 65 78 65 00 6f 70 65 72 61 2e 65 78 65 00 00 00 61 6d 69 67 6f 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = "/delete /tn SystemScript /f" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\ValueOfWindow" ascii //weight: 1
        $x_1_4 = "\"safebrowsing\":{\"enabled\":false}" ascii //weight: 1
        $x_1_5 = "Ly8gPT1Vc2VyU2NyaXB0PT0NCi8vIEBpbmNsdWRlIGh0dHA6Ly8qDQovLyBAaW5jbHVkZSBodHRwczovLyoNCi8vID09L1VzZXJTY3JpcHQ9PQ0KDQ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Radonskra_H_2147721940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Radonskra.H!bit"
        threat_id = "2147721940"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Radonskra"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "Ly8gPT1Vc2VyU2NyaXB0PT0NCi8vIEBpbmNsdWRlIGh0dHA6Ly8qDQovLyBAaW5jbHVkZSBodHRwczovLyoNCi8vID09L1VzZXJTY3JpcHQ9PQ0KDQ" ascii //weight: 1
        $x_1_3 = "\"safebrowsing\":{\"enabled\":false}" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\ValueOfWindow" ascii //weight: 1
        $x_1_5 = ".php?snid=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

