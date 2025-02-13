rule Trojan_Win32_DarkGateLoader_EB_2147891226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGateLoader.EB!MTB"
        threat_id = "2147891226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DLL_LoaderU" ascii //weight: 1
        $x_1_2 = "Storage not exists" ascii //weight: 1
        $x_1_3 = "corrupted data 2" ascii //weight: 1
        $x_1_4 = "script.au3" ascii //weight: 1
        $x_1_5 = "Autoit3.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGateLoader_AA_2147891620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGateLoader.AA!MTB"
        threat_id = "2147891620"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "301"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {89 16 8d 57 04 8b 12 33 90 ?? ?? 00 00 8d 4e 04 89 11 8d 57 08 8b 12 33 90 ?? ?? 00 00 8d 4e 08 89 11 8d 57 0c 8b 12 33 90 ?? ?? 00 00 8d 4e 0c 89 11 33 d2 8a 16 8a 92 ?? ?? ?? ?? 88 17}  //weight: 100, accuracy: Low
        $x_100_3 = {88 57 0f 8b 90 ?? ?? 00 00 31 17 8d 57 04 8b 88 ?? ?? 00 00 31 0a 8d 57 08 8b 88 ?? ?? 00 00 31 0a 8d 57 0c 8b 80 ?? ?? 00 00 31 02}  //weight: 100, accuracy: Low
        $x_100_4 = "zLAxuU0kQKf3sWE7ePRO2imyg9GSpVoYC6rhlX48ZHnvjJDBNFtMd1I5acwbqT+=" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGateLoader_MC_2147893995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGateLoader.MC!MTB"
        threat_id = "2147893995"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 55 08 8b 52 f8 8b 4d 08 8a 49 f6 80 e1 03 c1 e1 06 8b 5d 08 8a 5b f7 80 e3 3f 02 cb 88 4c 10 ff 8b 45 08 ff 40 f8 8b c7}  //weight: 5, accuracy: High
        $x_5_2 = "zLAxuU0kQKf3sWE7ePRO2imyg9GSpVoYC6rhlX48ZHnvjJDBNFtMd1I5acwbqT+=" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

