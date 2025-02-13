rule PWS_Win32_Stealer_M_2147621276_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Stealer.M"
        threat_id = "2147621276"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "\\Temp\\u16event.html" ascii //weight: 4
        $x_1_2 = "FindNextUrlCacheEntryA" ascii //weight: 1
        $x_1_3 = "FtpPutFileA" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
        $x_1_5 = "WindowsLive:name=*" ascii //weight: 1
        $x_1_6 = "Passport.Net\\*" ascii //weight: 1
        $x_1_7 = "Software\\Google\\Google Talk\\Accounts" ascii //weight: 1
        $x_1_8 = "\\yahoo.ini" ascii //weight: 1
        $x_1_9 = "\\Trillian\\users\\default" ascii //weight: 1
        $x_2_10 = "\\Steam.dll" ascii //weight: 2
        $x_1_11 = "\\Mozilla\\Firefox\\Profiles\\" ascii //weight: 1
        $x_1_12 = "Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2" ascii //weight: 1
        $x_2_13 = "HTTPMail Password2" ascii //weight: 2
        $x_1_14 = "Software\\Microsoft\\Internet Account Manager\\Accounts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_4_*) and 8 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Stealer_E_2147656497_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Stealer.E"
        threat_id = "2147656497"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 6d 74 70 5f 74 65 78 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 6d 74 70 5f 70 69 63 74 75 72 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {67 65 74 66 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {73 65 6e 64 66 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {67 65 74 70 61 73 73 00}  //weight: 1, accuracy: High
        $x_1_6 = {67 65 74 69 65 70 61 73 73 00}  //weight: 1, accuracy: High
        $x_1_7 = "smtp_picture::end" ascii //weight: 1
        $x_1_8 = {57 43 58 5f 46 54 50 2e 49 4e 49 00}  //weight: 1, accuracy: High
        $x_1_9 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 69 6d 61 67 65 2f 6a 70 65 67 3b 00}  //weight: 1, accuracy: High
        $x_1_10 = {69 65 5f 70 61 73 73 77 6f 72 64 73 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_11 = {2f 62 6f 74 6e 65 74 2f 75 70 6c 6f 61 64 2e 70 68 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Stealer_N_2147730748_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Stealer.N!bit"
        threat_id = "2147730748"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 c1 e0 04 03 c2 8b d1 03 4c 24 ?? c1 ea 05 03 54 24 ?? 33 c2 33 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d0 8b cd e8 ?? ?? ?? ?? 2b f8 59 59 8b cf 8b c7 c1 e9 ?? 03 4c 24 ?? c1 e0 ?? 03 44 24 ?? 33 c8 8d 04 3b 33 c8 8b 44 24 ?? 2b e9 6a f7 59 2b c8 8b 44 24 ?? 03 d9 8b 4c 24 ?? 4e 75 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Stealer_O_2147733577_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Stealer.O!bit"
        threat_id = "2147733577"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "InfoLogs/PC" ascii //weight: 1
        $x_1_2 = "Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = {68 6f 73 74 [0-16] 2e 68 6f 73 74 6c 61 6e 64 2e 70 72 6f 2f [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = "driverquery >>" ascii //weight: 1
        $x_1_5 = {56 4d 77 61 72 65 00 00 43 69 72 72 75 73 20 4c 6f 67 69 63}  //weight: 1, accuracy: High
        $x_1_6 = "ftp57.hostland.ru" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Stealer_V_2147742759_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Stealer.V!MTB"
        threat_id = "2147742759"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a1 48 d6 41 00 8d 97 ?? ?? ?? ?? 8a 8c 3e ?? ?? ?? ?? 56 88 0c 06 8b 0d 48 d6 41 00 e8 ?? ?? ?? ?? 83 fe 64 75 ?? 68 38 95 41 00 ff 35 4c d6 41 00 ff 15 30 40 41 00 a3 40 d6 41 00 46 3b f3 72}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be 04 0e 89 45 fc e8 ?? ?? ?? ?? 89 45 f8 8b 45 fc 33 45 f8 89 45 fc 8a 45 fc 88 04 0e 46 3b f2 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule PWS_Win32_Stealer_KM_2147755676_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Stealer.KM!MTB"
        threat_id = "2147755676"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e2 89 6c 24 ?? 89 54 24 ?? 8b 44 24 ?? ?? 44 24 ?? 8b 44 24 ?? ?? 44 24 ?? 81 3d ?? ?? ?? ?? 4a 04 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 e2 c7 45 ?? ?? ?? ?? ?? 89 55 ?? 8b 45 ?? ?? 45 ?? 8b 45 ?? ?? 45 ?? 81 3d ?? ?? ?? ?? 4a 04 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule PWS_Win32_Stealer_VM_2147760555_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Stealer.VM!MTB"
        threat_id = "2147760555"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c1 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02 0f 00 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

