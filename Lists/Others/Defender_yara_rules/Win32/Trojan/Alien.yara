rule Trojan_Win32_Alien_GA_2147795766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alien.GA!MTB"
        threat_id = "2147795766"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alien"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AlienRunPE" ascii //weight: 1
        $x_1_2 = "WebClient" ascii //weight: 1
        $x_1_3 = "RtlMoveMemory" ascii //weight: 1
        $x_1_4 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2f 00 [0-25] 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Alien_GMO_2147892235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alien.GMO!MTB"
        threat_id = "2147892235"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alien"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {57 42 22 c3 0e ba ?? ?? ?? ?? 5f ab 30 d7 42 6c 36 bf ?? ?? ?? ?? 40 e5 a6 08 ca 0a c8}  //weight: 10, accuracy: Low
        $x_10_2 = {6a b7 08 47 a4 35 ?? ?? ?? ?? 14 57}  //weight: 10, accuracy: Low
        $x_1_3 = "OptiLauncherU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Alien_MA_2147901654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alien.MA!MTB"
        threat_id = "2147901654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alien"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 54 24 08 33 c0 85 d2 7e 14 8b 4c 24 04 53 8a 1c 08 80 f3 cc 88 1c 08 40 3b c2 7c f2 5b c3}  //weight: 1, accuracy: High
        $x_1_2 = "-decode" ascii //weight: 1
        $x_1_3 = "All Users\\MsMpEng\\MpSvc.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Alien_AMMF_2147906407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alien.AMMF!MTB"
        threat_id = "2147906407"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alien"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1b ca c6 bb c5 b6 a2 32 c6 25 e5 48 8e b2 8b fb 76 42 35 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Alien_AHB_2147953937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alien.AHB!MTB"
        threat_id = "2147953937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alien"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Create persistent scheduled task" ascii //weight: 10
        $x_10_2 = "Get GitHub URL from Pastebin" ascii //weight: 10
        $x_10_3 = "Execute as background process" ascii //weight: 10
        $x_20_4 = "function Download-FileWithRetries" ascii //weight: 20
        $x_50_5 = "$githubUrl = (Invoke-WebRequest -Uri $pastebinUrl -UseBasicParsing -ErrorAction Stop).Content.Trim()" ascii //weight: 50
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

