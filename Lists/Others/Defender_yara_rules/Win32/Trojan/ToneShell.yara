rule Trojan_Win32_ToneShell_EC_2147923829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ToneShell.EC!MTB"
        threat_id = "2147923829"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ToneShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/C schtasks /F /Create /TN FFWallpaperEmbCore /SC minute /MO 6 /TR \"C:\\ProgramData\\FFWallpaperCore\\SFFWallpaperCore.exe" ascii //weight: 3
        $x_1_2 = "ZackAllen......techyteachme Ok" ascii //weight: 1
        $x_1_3 = "Start...buitengebieden" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ToneShell_CH_2147956131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ToneShell.CH!MTB"
        threat_id = "2147956131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ToneShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c6 45 d4 73 c6 45 d5 68 c6 45 d6 65 c6 45 d7 6c c6 45 d8 6c c6 45 d9 33 c6 45 da 32 c6 45 db 2e c6 45 dc 64 c6 45 dd 6c c6 45 de 6c c6 45 df 00}  //weight: 2, accuracy: High
        $x_1_2 = "Global\\abdfBsk_once" ascii //weight: 1
        $x_1_3 = "cmd.exe /c format" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

