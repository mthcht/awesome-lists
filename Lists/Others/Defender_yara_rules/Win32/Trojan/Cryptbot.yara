rule Trojan_Win32_Cryptbot_YL_2147744621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptbot.YL!MSR"
        threat_id = "2147744621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%ProgramData%\\Cryptbot\\margin.exe" wide //weight: 1
        $x_1_2 = "HKCU\\Software\\Cryptbot Software\\Cryptbot" wide //weight: 1
        $x_1_3 = "wallet.dat" wide //weight: 1
        $x_1_4 = "\\Files\\Coins\\" wide //weight: 1
        $x_1_5 = "FilePasswords.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cryptbot_GLM_2147808278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptbot.GLM!MTB"
        threat_id = "2147808278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {b9 22 8d 2a 8b 09 20 89 f9 31 39 ab 22 b4 28 2b 33 1d 45 08 e5 31 48 d3 b4 84 b1 28 91 5e 76 51 31 f5 e1 5c}  //weight: 10, accuracy: High
        $x_1_2 = "GetUserName" ascii //weight: 1
        $x_1_3 = "URLDownloadToFile" ascii //weight: 1
        $x_1_4 = "ShellExecute" ascii //weight: 1
        $x_1_5 = "CryptUnprotectData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cryptbot_GNM_2147810544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptbot.GNM!MTB"
        threat_id = "2147810544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b ce 81 c0 27 fa 2b d4 33 c6 83 c0 53 89 45 f0}  //weight: 10, accuracy: High
        $x_1_2 = "JvEqy(kernel32.dll" ascii //weight: 1
        $x_1_3 = "]kVkernel32.dll" ascii //weight: 1
        $x_1_4 = "$8JvEqy(kernel32.dll" ascii //weight: 1
        $x_1_5 = "Ykernel32.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cryptbot_BPD_2147927767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptbot.BPD!MTB"
        threat_id = "2147927767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 08 0f 6a 2a 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cryptbot_ACB_2147932183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptbot.ACB!MTB"
        threat_id = "2147932183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {0f b6 d0 89 95 f8 fe ff ff 8a 8c 15 fc fe ff ff 0f b6 c1 03 c3 0f b6 d8 8a 84 1d fc fe ff ff 88 84 15 fc fe ff ff 8b 85 f8 fe ff ff 0f b6 d1 88 8c 1d fc fe ff ff 0f b6 8c 05 fc fe ff ff 03 d1 0f b6 ca 0f b6 8c 0d fc fe ff ff 30 4e ff 83 ef 01}  //weight: 3, accuracy: High
        $x_2_2 = "oSabnN" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cryptbot_YLH_2147932985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptbot.YLH!MTB"
        threat_id = "2147932985"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 08 0f 0a 64 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

