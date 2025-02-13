rule Trojan_Win64_Stealer_O_2147841133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.O!MSR"
        threat_id = "2147841133"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Google\\Chrome\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_2 = "Microsoft\\Edge\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_3 = "Browser\\User Data\\Local State" ascii //weight: 1
        $x_1_4 = "ImBetter.pdb" ascii //weight: 1
        $x_1_5 = "password:" ascii //weight: 1
        $x_1_6 = "ChromeCookies" ascii //weight: 1
        $x_1_7 = "BraveCookies" ascii //weight: 1
        $x_1_8 = "TitanCookies" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_PADB_2147900956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.PADB!MTB"
        threat_id = "2147900956"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Program Files (x86)\\Windows Defender\\MpHeadlessRun.exe" ascii //weight: 1
        $x_1_2 = "Application added to startup successfully." ascii //weight: 1
        $x_1_3 = "Make sure to run the program with administrator privileges" ascii //weight: 1
        $x_1_4 = "stealer\\x64\\Release\\stealer.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_SO_2147902568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.SO!MTB"
        threat_id = "2147902568"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "PuffierIndus" ascii //weight: 2
        $x_2_2 = "GuldenRuche for Windows" ascii //weight: 2
        $x_2_3 = "GuldenRuche" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_RP_2147911246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.RP!MTB"
        threat_id = "2147911246"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 50 50 44 41 54 41 00 5c 68 74 64 6f 63 73 5c 00 00 00 00 00 00 00 00 5c 6f 75 74 70 75 74 2e 65 78 65 00 5c 00 00 00 43 3a 5c 00 44 3a 5c 00 45 3a 5c 00 46 3a 5c 00 47 3a 5c 00 48 3a 5c 00 49 3a 5c 00 5a 3a 5c}  //weight: 1, accuracy: High
        $x_1_2 = "\\ConsoleApplication1.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_WZ_2147918410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.WZ!MTB"
        threat_id = "2147918410"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "runtime.stealWork" ascii //weight: 1
        $x_1_2 = "/Desktop/Stealer/main.go" ascii //weight: 1
        $x_1_3 = "Go build ID: " ascii //weight: 1
        $x_1_4 = "h1:H+t6A/QJMbhCSEH5rAuRxh+CtW96g0Or0Fxa9IKr4uc=" ascii //weight: 1
        $x_1_5 = "main.reverseString" ascii //weight: 1
        $x_1_6 = "type:.eq.main.Response" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Stealer_GD_2147929221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealer.GD!MTB"
        threat_id = "2147929221"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "88.119.167.239" ascii //weight: 5
        $x_1_2 = "qulonglong" ascii //weight: 1
        $x_1_3 = "remove_me_from_pool" ascii //weight: 1
        $x_1_4 = "bot2world_connected" ascii //weight: 1
        $x_1_5 = "bot2world_ready_read" ascii //weight: 1
        $x_1_6 = "bot2server_connected" ascii //weight: 1
        $x_1_7 = "bot2server_ready_read" ascii //weight: 1
        $x_1_8 = "\\Shell\\Open\\Command" ascii //weight: 1
        $x_1_9 = "KeyboardModifier" ascii //weight: 1
        $x_1_10 = "mailto" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

