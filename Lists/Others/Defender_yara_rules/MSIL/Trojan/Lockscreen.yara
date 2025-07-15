rule Trojan_MSIL_Lockscreen_C_2147712469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lockscreen.C!bit"
        threat_id = "2147712469"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lockscreen"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 32 68 31 64 47 52 76 64 32 34 75 5a 58 68 6c [0-16] 4c 58 49 67 4c 58 51 67 4d 41 3d 3d}  //weight: 1, accuracy: Low
        $x_1_2 = "IC9DIHJlZyBhZGQgIkhLTE1cU09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3MgTlRcQ3VycmVudFZlcnNpb25cV2lubG9nb24iIC92IFNoZWxsIC90IFJFR19TWiAvZCAiIiAvZiA=" ascii //weight: 1
        $x_1_3 = "IC9DIHJlZyBhZGQgIkhLTE1cU09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3MgTlRcQ3VycmVudFZlcnNpb25cV2lubG9nb24iIC92IFVzZXJpbml0IC90IFJFR19TWiAvZCAidXNlcmluaXQuZXhlLA==" ascii //weight: 1
        $x_1_4 = "IC9DIHJlZyBhZGQgIkhLTE1cU09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVuIiAvdiAiTGF1bmNoVE0iIC90IFJFR19TWiAvZCAi" ascii //weight: 1
        $x_1_5 = {50 6f 77 65 72 65 64 42 79 41 74 74 72 69 62 75 74 65 00 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 2e 41 74 74 72 69 62 75 74 65 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lockscreen_2147731668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lockscreen"
        threat_id = "2147731668"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lockscreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tastatu has locked your comptuer for using leaked software!" ascii //weight: 1
        $x_1_2 = "This porgram has disabled task manager and antiviruses." ascii //weight: 1
        $x_1_3 = "\\Tastatu\\obj\\Debug\\Tastatu.pdb" ascii //weight: 1
        $x_1_4 = "Lock Type Meaning: Unbreakable Lock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lockscreen_SOP_2147923708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lockscreen.SOP!MTB"
        threat_id = "2147923708"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lockscreen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 13 00 00 04 6f 87 00 00 0a 1d 28 88 00 00 0a 72 ?? ?? ?? 70 28 89 00 00 0a 17 28 8a 00 00 0a 00 1d 28 88 00 00 0a 72 ?? ?? ?? 70 28 89 00 00 0a 19 73 8b 00 00 0a 80 15 00 00 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lockscreen_PAE_2147924247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lockscreen.PAE!MTB"
        threat_id = "2147924247"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lockscreen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Jenit_s_Screen_Locker" ascii //weight: 2
        $x_2_2 = "https://pastebin.com/raw/v4ZN7mmj" wide //weight: 2
        $x_1_3 = "infected with Trojan-type spyware" wide //weight: 1
        $x_1_4 = "Microsoft\\Windows\\Start Menu\\Programs\\Startup" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lockscreen_PDR_2147940942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lockscreen.PDR!MTB"
        threat_id = "2147940942"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lockscreen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Keygroup777" wide //weight: 3
        $x_2_2 = "Omnilocker - BANG!" wide //weight: 2
        $x_1_3 = "taskkill /im explorer.exe /f" wide //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lockscreen_PAHI_2147946359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lockscreen.PAHI!MTB"
        threat_id = "2147946359"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lockscreen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_2_2 = "DisableTaskMgr" wide //weight: 2
        $x_1_3 = "/k taskkill /f /im explorer.exe" wide //weight: 1
        $x_2_4 = "Your system has been destroyed" wide //weight: 2
        $x_2_5 = "\\\\.\\PhysicalDrive0" wide //weight: 2
        $x_1_6 = "Failed to write to MBR" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

