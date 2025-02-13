rule Trojan_Win32_Dinwod_SB_2147752624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dinwod.SB!MSR"
        threat_id = "2147752624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dinwod"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "www.2ihsfa.com" ascii //weight: 5
        $x_5_2 = "http://hfuie32.2ihsfa.com" ascii //weight: 5
        $x_5_3 = "http://reach.cp-back.biz" ascii //weight: 5
        $x_1_4 = "Software\\iwqggtf\\data" wide //weight: 1
        $x_1_5 = "manager/account_settings/account_billing" wide //weight: 1
        $x_1_6 = "CryptUnprotectData" ascii //weight: 1
        $x_1_7 = "FBCookies.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dinwod_A_2147783206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dinwod.A!MTB"
        threat_id = "2147783206"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dinwod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f af 37 46 89 30 8b 09 8b 74 24 0c 8b 06 0f b7 4c 8a 02}  //weight: 1, accuracy: High
        $x_1_2 = {32 06 5f 66 0f b6 c8 0f b7 c9 01 0e 8b 13 8b 75 14 8d 54 96 fc 01 0a}  //weight: 1, accuracy: High
        $x_1_3 = "btlc.dat" ascii //weight: 1
        $x_1_4 = "(kiss)" ascii //weight: 1
        $x_1_5 = "what the fuck is that" ascii //weight: 1
        $x_1_6 = "crazy bitch" ascii //weight: 1
        $x_1_7 = "nice ass:*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dinwod_AM_2147813297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dinwod.AM!MTB"
        threat_id = "2147813297"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dinwod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vguarder.91i.net/user.htm" ascii //weight: 1
        $x_1_2 = "updatex.exe" ascii //weight: 1
        $x_1_3 = "Serverx.exe" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dinwod_RPY_2147887410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dinwod.RPY!MTB"
        threat_id = "2147887410"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dinwod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "test.besthotel360.com" ascii //weight: 1
        $x_1_2 = "puppet.Txt" ascii //weight: 1
        $x_1_3 = "VMProtect begin" ascii //weight: 1
        $x_1_4 = "Sleep" ascii //weight: 1
        $x_1_5 = "GetTickCount" ascii //weight: 1
        $x_1_6 = "HttpOpenRequestA" ascii //weight: 1
        $x_1_7 = "Mozilla/4.0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

