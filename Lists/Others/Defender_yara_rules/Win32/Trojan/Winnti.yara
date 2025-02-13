rule Trojan_Win32_Winnti_A_2147689666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Winnti.A!dha"
        threat_id = "2147689666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 11 3a 10 75 ?? 84 d2 74 ?? 8a 51 01 3a 50 01 75 ?? 83 c1 02 83 c0 02 84 d2 75 ?? 33 c0 eb ?? 1b c0 83 d8 ff 85 c0 74 ?? 43 83 c6 04}  //weight: 1, accuracy: Low
        $x_1_2 = {00 52 53 44 53}  //weight: 1, accuracy: High
        $x_1_3 = "netsvcs" ascii //weight: 1
        $x_1_4 = "SetAppInitDllDataInf" ascii //weight: 1
        $x_1_5 = "\\svchost.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Winnti_E_2147689682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Winnti.E!dha"
        threat_id = "2147689682"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {62 61 73 5f 5f 2e 66 6f 6e [0-5] 66 6f 6e 74 73 5c [0-16] 5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 25 64 [0-16] 53 43 53 49 44 49 53 4b [0-16] 5c 5c 2e 5c 53 63 73 69 25 64 3a}  //weight: 4, accuracy: Low
        $x_1_2 = "\\Driver\\Tcpip" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Winnti_G_2147689683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Winnti.G!dha"
        threat_id = "2147689683"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[wd]:RemoteInject %s" ascii //weight: 1
        $x_1_2 = "[wd]deletemeCmd:%s" ascii //weight: 1
        $x_1_3 = {64 65 6c 20 25 25 30 00 2e 62 61 74}  //weight: 1, accuracy: High
        $x_1_4 = {77 69 6e 64 30 77 73 00 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 25 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Winnti_B_2147689684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Winnti.B!dha"
        threat_id = "2147689684"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "300"
        strings_accuracy = "Low"
    strings:
        $x_300_1 = {8a c8 80 e1 0f c0 e1 04 c0 e8 04 02 c8 88 0c ?? ?? 3b ?? 72 e6}  //weight: 300, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Winnti_D_2147689686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Winnti.D!dha"
        threat_id = "2147689686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "find system svchost.exe" ascii //weight: 1
        $x_1_2 = "GetSystemsvcHostProcessId Return %d" ascii //weight: 1
        $x_1_3 = "StartInject %s to %d Success!" ascii //weight: 1
        $x_1_4 = "DeleteMyself Over!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Winnti_F_2147689687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Winnti.F!dha"
        threat_id = "2147689687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {80 7c 24 29 5a 75 0d}  //weight: 2, accuracy: High
        $x_1_2 = "\\??\\%s\\drivers\\%s.sys" ascii //weight: 1
        $x_1_3 = "Global\\%s" ascii //weight: 1
        $x_1_4 = "cmd=0x%X" ascii //weight: 1
        $x_1_5 = "Lscsvc.dll" ascii //weight: 1
        $x_1_6 = "usbmsg" ascii //weight: 1
        $x_1_7 = "CONNECT %s:%d HTTP/1.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Winnti_2147692926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Winnti!dha"
        threat_id = "2147692926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 6e 73 74 61 6c 6c 00 54 73 65 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {33 c0 66 8b 02 8b e8 81 e5 00 f0 ff ff 81 fd 00 30 00 00 75 0d 8b 6c 24 18 25 ff 0f 00 00 03 c7 01 28 8b 41 04 46 83 e8 08 83 c2 02 d1 e8 3b f0 72}  //weight: 1, accuracy: High
        $x_1_3 = {8b 07 8b c8 8b d0 c1 e9 1d c1 ea 1e 8b f0 83 e1 01 83 e2 01 c1 ee 1f a9 00 00 00 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Winnti_O_2147707047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Winnti.O!dha"
        threat_id = "2147707047"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\cryptbase.dll" ascii //weight: 1
        $x_1_2 = "sysprep.exe" ascii //weight: 1
        $x_1_3 = {73 74 61 72 74 20 25 73 0d 0a 20 64 65 6c 20 25 25 30 00}  //weight: 1, accuracy: High
        $x_1_4 = {61 76 70 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_10_5 = {6d 73 69 65 78 65 63 2e 65 78 65 00 74 61 67 00 76 65 72 00 67 72 6f 75 70 00 00 00 75 72 6c 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Winnti_Q_2147707050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Winnti.Q!dha"
        threat_id = "2147707050"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "inst  <Backdoor> [DriverLetter]   :    Install HDD" ascii //weight: 1
        $x_1_2 = "HDD Rootkit" ascii //weight: 1
        $x_1_3 = "\\i386\\HddInstall.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Winnti_N_2147711359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Winnti.N!dha"
        threat_id = "2147711359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b1 99 75 15 33 c0 85 f6 7e 0f 8a 14 18 32 d1 fe c1 88 14 18 40 3b c6 7c f1}  //weight: 1, accuracy: High
        $x_1_2 = {8a 04 31 34 [0-1] 8a d0 c0 e2 04 c0 e8 04 02 d0 88 14 31 8b 45 00 41 3b c8 72 e6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Winnti_U_2147717719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Winnti.U!dha"
        threat_id = "2147717719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2d 6b 20 6e 65 74 73 76 63 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {61 76 70 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "workdll64.dll" ascii //weight: 1
        $x_1_4 = {41 0f b6 0b ff c2 49 ff c3 80 f1 36 0f b6 c1 c0 e9 04 c0 e0 04 02 c1 41 88 43 ff 3b 13 72 e1}  //weight: 1, accuracy: High
        $x_1_5 = {43 4f 4e 4e 45 43 54 20 25 73 3a 25 64 20 48 54 54 50 2f 31 2e 30 0d 0a 0d 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Winnti_V_2147718073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Winnti.V!dha"
        threat_id = "2147718073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "{332222A-33A3-2222-AAAA-3A22AA333}" ascii //weight: 1
        $x_1_2 = {69 62 20 2d ?? ?? ?? 72 20 2d 73 ?? ?? ?? 20 2d 68 25 ?? ?? ?? 25 31 0d 0a ?? ?? ?? 3a 25 75 0d ?? ?? ?? 0a 64 65 6c ?? ?? ?? 20 25 25 31}  //weight: 1, accuracy: Low
        $x_1_3 = {33 36 30 41 [0-7] 6e 74 69 48 [0-7] 61 63 6b 65 [0-7] 72 36 34 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Winnti_ZD_2147741720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Winnti.ZD!dha"
        threat_id = "2147741720"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 34 08 09 40 3b 45 ?? 7c f6}  //weight: 1, accuracy: Low
        $x_1_2 = {5f 60 7b 7d c7 85 ?? ?? ?? ?? 7c 68 65 48 c7 85 ?? ?? ?? ?? 65 65 66 6a}  //weight: 1, accuracy: Low
        $x_1_3 = {4a 7b 6c 68 c7 85 ?? ?? ?? ?? 7d 6c 59 7b c7 85 ?? ?? ?? ?? 66 6a 6c 7a 66 c7 85 ?? ?? ?? ?? 7a 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Winnti_EM_2147896941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Winnti.EM!MTB"
        threat_id = "2147896941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 5c 0c 40 32 da 88 5c 0c 40 41 3b c8 7c f1}  //weight: 1, accuracy: High
        $x_1_2 = "gethostbyname" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_4 = "microsoft.ns02.us" ascii //weight: 1
        $x_1_5 = "wins.kozow.com" ascii //weight: 1
        $x_1_6 = "explorer.exe" ascii //weight: 1
        $x_1_7 = "Terminal Server\\Wds\\rdpwd\\Tds\\tcp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

