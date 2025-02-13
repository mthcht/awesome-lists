rule Trojan_Win32_Cinmeng_B_2147607470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cinmeng.B"
        threat_id = "2147607470"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cinmeng"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Webbrowser.browser.1" ascii //weight: 1
        $x_1_2 = "WEBBROWSERLibWWW" ascii //weight: 1
        $x_1_3 = {77 65 62 62 72 6f 77 73 65 72 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_4 = {38 38 41 46 2d 31 33 44 35 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d 39 46 42 38 38 36 39 38 43 46 43 31 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cinmeng_C_2147622026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cinmeng.C"
        threat_id = "2147622026"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cinmeng"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 6e 70 72 6f 63 53 65 72 76 65 72 33 32 00 00 7b 33 38 35 41 42 38 43 36 2d 46 42 32 32 2d 34 44 31 37 2d 38 38 33 34 2d 30 36 34 45 32 42 41 30 41 36 46 30 7d}  //weight: 1, accuracy: High
        $x_1_2 = {48 6f 6f 6b 56 65 72 00 48 6f 6f 6b 43 6f 6e 66 69 67 00 00 48 6f 6f 6b 46 6e 61 6d 65 00 00 00 43 6f 6e 66 69 67 2e 63 66 67}  //weight: 1, accuracy: High
        $x_1_3 = "MircrGFX.dat" ascii //weight: 1
        $x_1_4 = "d3d1caps.SRG" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" ascii //weight: 1
        $x_1_6 = {68 2c 5a d0 00 8d 4d d0 e8 f6 a2 ff ff 3b f3 74 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cinmeng_17576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cinmeng"
        threat_id = "17576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cinmeng"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 61 00 63 00 70 00 69 00 64 00 69 00 73 00 6b 00 00 00 00 00 49 00 6d 00 61 00 67 00 65 00 50 00 61 00 74 00 68 00 00 00 ?? ?? 01 00 ?? ?? 01 00 ?? ?? 01 00 ?? ?? 01 00 5c 00 77 00 69 00 6e 00 6c 00 69 00 62 00 20 00 2e 00 64 00 6c 00 6c 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cinmeng_17576_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cinmeng"
        threat_id = "17576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cinmeng"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "acpidisk.sys" ascii //weight: 2
        $x_1_2 = "FirstInstall" ascii //weight: 1
        $x_2_3 = "BDC4D3E8DB9A298" ascii //weight: 2
        $x_2_4 = "mscpx32r.det" ascii //weight: 2
        $x_2_5 = "\\\\.\\pipe\\A09C7C26ED857C36" ascii //weight: 2
        $x_1_6 = "SOFTWARE\\Microsoft\\IDSCNP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cinmeng_17576_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cinmeng"
        threat_id = "17576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cinmeng"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {42 49 00 6d 00 61 00 67 00 65 00 50 00 61 00 74 00 68 00 00 00 5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 61 00 63 00 70 00 69 00 64 00 69 00 73 00 6b 00 00 00 00 00 5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 61 00 63 00 70 00 69 00 64 00 69 00 73 00 6b 00 00 00 55 8b ec 83 ec 1c 53 56 57 [0-5] 00 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = "\\winlib .dll" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cinmeng_17576_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cinmeng"
        threat_id = "17576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cinmeng"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "PsSetCreateProcessNotifyRoutine" ascii //weight: 1
        $x_1_2 = "ExFreePool" ascii //weight: 1
        $x_1_3 = "MmMapLockedPagesSpecifyCache" ascii //weight: 1
        $x_10_4 = {5f 5e 5b c9 c2 08 00 [0-1] 5c 00 42 00 61 00 73 00 65 00 4e 00 61 00 6d 00 65 00 64 00 4f 00 62 00 6a 00 65 00 63 00 74 00 73 00 5c 00 55 00 49 00 44 00 5f 00 31 00 33 00 32 00 39 00 31 00 34 00 37 00 36 00 30 00 32 00 5f 00 4d 00 49 00 45 00 45 00 76 00 65 00 6e 00 74 00 00 00 55 8b ec 83 ec 0c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cinmeng_17576_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cinmeng"
        threat_id = "17576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cinmeng"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {70 5f 73 74 61 72 5f 31 2e 6a 70 67 00 00 00 00 78 5f 37 31 33 33 2e 64 6c 6c}  //weight: 3, accuracy: High
        $x_2_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Ext\\Settings\\{E5A7A15F-213F-4FCF-8DE7-D388F9FB09EB}" ascii //weight: 2
        $x_3_3 = {42 49 4e 00 25 73 5c 63 6e 77 69 6e 2e 64 6c 6c}  //weight: 3, accuracy: High
        $x_1_4 = "SOFTWARE\\Microsoft\\IDSCNP" ascii //weight: 1
        $x_2_5 = "C:\\WINDOWS\\SYSTEM32\\cnwin.dll" wide //weight: 2
        $x_1_6 = "IEHelper1Setup Version 1.0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Cinmeng_17576_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cinmeng"
        threat_id = "17576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cinmeng"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://update.cnnewmusic.com/get_gif.php?" ascii //weight: 5
        $x_5_2 = "CLSID\\{E5A7A15F-213F-4FCF-8DE7-D388F9FB09EB}" ascii //weight: 5
        $x_5_3 = "CLSID\\{385AB8C6-FB22-4D17-8834-064E2BA0A6F0}" ascii //weight: 5
        $x_5_4 = "SOFTWARE\\Microsoft\\IDSCNP" ascii //weight: 5
        $x_2_5 = "music.gif" ascii //weight: 2
        $x_5_6 = "cnwin downloaded completed!" ascii //weight: 5
        $x_5_7 = "login.yiqilai.com" ascii //weight: 5
        $x_2_8 = "51mp3.com" ascii //weight: 2
        $x_2_9 = "MircrGFX.dat" ascii //weight: 2
        $x_2_10 = "d3d1caps.SRG" ascii //weight: 2
        $x_3_11 = "/get_a.php?fid=%d&kid=%d&cnt=%d&mac=%s&kw=%s&version=%s&uuid=%s" ascii //weight: 3
        $x_5_12 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\{16B770A0-0E87-4278-B748-2460D64A8386}" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_5_*) and 3 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

