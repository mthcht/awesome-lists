rule BrowserModifier_Win32_Monkostey_235975_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Monkostey"
        threat_id = "235975"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkostey"
        severity = "19"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "explorer.exe http://uninstall.mysafesavings.com" ascii //weight: 1
        $x_1_2 = "Microsoft\\WindowsLogger\\winlogger.exe" ascii //weight: 1
        $x_1_3 = "Software\\MySafeSavings" ascii //weight: 1
        $x_1_4 = {67 72 69 6c 00 46 69 6e 64 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Monkostey_235975_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Monkostey"
        threat_id = "235975"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkostey"
        severity = "19"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 0c 53 33 db 83 7d 08 02 c6 45 ?? 65 c6 45 ?? 6e c6 45 ?? 4d c6 45 ?? 75 c6 45 ?? 52 c6 45 ?? 61}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 d4 50 6a 02 53 89 75 d4 c7 45 ?? 03 00 00 00 89 75 ?? 89 75 ?? 89 75 ?? ff 15 ?? ?? ?? ?? 53 8b f0 ff d7 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {ff d7 53 6a 26 bd ?? ?? ?? ?? 55 53 ff d6 68 ?? ?? ?? ?? 55 ff d7 53 6a 23 bd ?? ?? ?? ?? 55 53 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Monkostey_235975_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Monkostey"
        threat_id = "235975"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkostey"
        severity = "19"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 73 58 6a 69 66 89 ?? ?? 58 6a 4d 66 89 ?? ?? 58 6a 61 66 89 ?? ?? 58 66 89 ?? ?? 6a 53 33 c0 66 89 ?? ?? 58 6a 66}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 08 66 83 f9 2d 74 ?? 66 83 f9 2f 0f ?? ?? 00 00 00 6a 73 59 6a 61 66 89 4d ?? 66 89 4d ?? 59 6a 6d 66 89 4d ?? 59 66 89 4d ?? 33 c9 6a 73}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 46 10 04 00 00 00 89 5e 14 89 5e 18 89 5e 1c 89 5e 20 89 5d fc 68 08 02 00 00 8d 46 3c 53 50 c7 ?? ?? ?? ?? 00 88 5e 28 89 5e 2c c7 46 34 e8 03 00 00 89 5e 38 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Monkostey_235975_3
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Monkostey"
        threat_id = "235975"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkostey"
        severity = "19"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ProxyServer" ascii //weight: 1
        $x_1_2 = "network.proxy.type" ascii //weight: 1
        $x_1_3 = "Vwin_iocp_io_service@" ascii //weight: 1
        $x_1_4 = "Vconnection@proxy@" ascii //weight: 1
        $x_1_5 = {68 74 74 70 3d 25 73 3a 25 73 00 00 58 58 58 00 48 4f 53 54 00 00 00 00 55 73 65 72 2d 41 67 65 6e 74 00 00 31 30 30 00 73 65 72 76 69 63 65}  //weight: 1, accuracy: High
        $x_1_6 = "FDfbID" ascii //weight: 1
        $x_1_7 = {83 7d 08 02 8b 45 0c c6 45 ?? 6f c6 45 ?? 6e c6 45 ?? 75 c6 45 ?? 46 c6 45 ?? 00}  //weight: 1, accuracy: Low
        $x_2_8 = ".?AVCFindingDiscountApp@@" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Monkostey_235975_4
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Monkostey"
        threat_id = "235975"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkostey"
        severity = "19"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "finding.discount" wide //weight: 1
        $x_1_2 = {64 00 62 00 67 00 2e 00 70 00 68 00 70 00 3f 00 61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 4d 00 61 00 69 00 6e 00 44 00 6c 00 67 00 53 00 74 00 61 00 72 00 74 00 26 00 49 00 45 00 3d 00 ?? ?? ?? ?? ?? ?? 26 00 4f 00 53 00 3d 00 ?? ?? ?? ?? ?? ?? 26 00 74 00 65 00 73 00 74 00 3d 00 [0-6] 26 00 55 00 73 00 65 00 72 00 49 00 64 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_3 = "ratings/rate.php?cmd=get&id=" wide //weight: 1
        $x_1_4 = "softwaredebughelp.com" wide //weight: 1
        $x_10_5 = "SafeSavings\\config.dat" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

