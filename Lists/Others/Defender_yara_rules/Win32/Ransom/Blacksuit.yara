rule Ransom_Win32_Blacksuit_AD_2147895351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Blacksuit.AD!MTB"
        threat_id = "2147895351"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Blacksuit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "301"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {8b c6 8d 0c 37 33 d2 46 f7 74 24 ?? 8a 82 ?? ?? ?? ?? 32 04 0b 88 01 81 fe ?? ?? 00 00 72}  //weight: 100, accuracy: Low
        $x_100_3 = "readme.blacksuit.txt" wide //weight: 100
        $x_100_4 = "BEGIN RSA PUBLIC KEY" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Blacksuit_SA_2147896743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Blacksuit.SA!MTB"
        threat_id = "2147896743"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Blacksuit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c vssadmin delete shadows /all /quiet" wide //weight: 1
        $x_1_2 = "readme.blacksuit.txt" wide //weight: 1
        $x_1_3 = "-BEGIN RSA PUBLIC KEY-" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Blacksuit_PA_2147913843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Blacksuit.PA!MTB"
        threat_id = "2147913843"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Blacksuit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "locker_" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "readme.blacksuit.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

