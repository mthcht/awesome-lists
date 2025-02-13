rule Trojan_Win32_Katusha_BE_2147819298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Katusha.BE!MTB"
        threat_id = "2147819298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Katusha"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 1e f7 1e 31 1e 29 1e 81 06 2d 70 e5 ff 01 1e 83 c6 04 4a 0f 85}  //weight: 2, accuracy: High
        $x_2_2 = "MxOsTjVeX7B2rF1.Ivo" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Katusha_RPZ_2147824964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Katusha.RPZ!MTB"
        threat_id = "2147824964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Katusha"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" ascii //weight: 1
        $x_1_2 = "IEX(New-Object Net.WebClient)" ascii //weight: 1
        $x_1_3 = "DownloadString('https://cdn.discordapp.com" ascii //weight: 1
        $x_1_4 = "bypassModuleObfuscated.bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

