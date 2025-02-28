rule Trojan_Win32_Fsysna_GM_2147755704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fsysna.GM!MTB"
        threat_id = "2147755704"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 99 f7 fe 8a 44 14 0c 30 04 19 41 81 f9 [0-4] 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fsysna_ARA_2147837127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fsysna.ARA!MTB"
        threat_id = "2147837127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Global\\3pc6RWOgectGTFqCowxjeGy3XIGPtLwNrsr2zDctYD4hAU5pj4GW7rm8gHrHyTB6" ascii //weight: 2
        $x_2_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_2_3 = "onsapay.com/loader" ascii //weight: 2
        $x_2_4 = "\\TEMP\\AAAAAAAAAAAAAAA.exe" ascii //weight: 2
        $x_2_5 = "\\TEMP\\spoolsv.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fsysna_GND_2147893563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fsysna.GND!MTB"
        threat_id = "2147893563"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "server.com/virus.exe" ascii //weight: 1
        $x_1_2 = "tmpjhgTFztfZ789tfzTDt" ascii //weight: 1
        $x_1_3 = "virus.exeIGDAIEjhMWNJXB" ascii //weight: 1
        $x_1_4 = "annofaie" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fsysna_AS_2147896265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fsysna.AS!MTB"
        threat_id = "2147896265"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "ShellExecuteA" ascii //weight: 5
        $x_5_2 = "URLDownloadToFileA" ascii //weight: 5
        $x_5_3 = "C:\\ProgramData\\svchost.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fsysna_GMX_2147934045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fsysna.GMX!MTB"
        threat_id = "2147934045"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 d2 02 d2 c0 eb 04 0a d3 88 16 0f b6 50 01 0f b6 18 0f b6 94 15 ?? ?? ?? ?? 0f b6 9c 1d ?? ?? ?? ?? c0 ea 02 c0 e3 04 0a d3 88 56 01 0f b6 50 01 0f b6 94 15 ?? ?? ?? ?? 0f b6 58 02 c0 e2 06 0a 94 1d ?? ?? ?? ?? 83 c6 03 88 56 ff 83 c0 04 4f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fsysna_NITs_2147934878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fsysna.NITs!MTB"
        threat_id = "2147934878"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "vssadmin delete shadows /all /quiet" wide //weight: 2
        $x_2_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 2
        $x_2_3 = "LegalNoticeText" wide //weight: 2
        $x_2_4 = "LegalNoticeCaption" wide //weight: 2
        $x_1_5 = "Esmeralda Ransomware" ascii //weight: 1
        $x_1_6 = "How_To_Decrypt" wide //weight: 1
        $x_1_7 = "BeginUpdateResourceW" ascii //weight: 1
        $x_1_8 = "EndUpdateResourceW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

