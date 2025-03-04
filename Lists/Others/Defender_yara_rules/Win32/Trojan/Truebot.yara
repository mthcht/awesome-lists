rule Trojan_Win32_TrueBot_A_2147729936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrueBot.A!MTB"
        threat_id = "2147729936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrueBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\dat_tmp.DAT" ascii //weight: 1
        $x_1_2 = "/C systeminfo >> %s" ascii //weight: 1
        $x_1_3 = "/C net view  >> %s" ascii //weight: 1
        $x_1_4 = "/C ipconfig  >> %s" ascii //weight: 1
        $x_1_5 = "/C whoami  >> %s" ascii //weight: 1
        $x_1_6 = "%smod/info.php" ascii //weight: 1
        $x_1_7 = "%s\\Defender_TEMP_%08x.exe" ascii //weight: 1
        $x_1_8 = "SoftWare\\MicroSoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrueBot_ZZ_2147833896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrueBot.ZZ"
        threat_id = "2147833896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrueBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "401"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = "n=%s&o=%s&a=%d&u=%s&p=%s&d=%s" ascii //weight: 100
        $x_100_3 = {8d 45 fc 50 6a 64 6a 00 (e8|ff 15)}  //weight: 100, accuracy: Low
        $x_100_4 = {8b 55 fc 52 8b 4a 10 8b 42 0c 89 85 ?? ff ff ff 89 8d ?? ff ff ff (e8|ff 15)}  //weight: 100, accuracy: Low
        $x_100_5 = {68 18 01 00 00 8d 85 ?? fe ff ff 6a 00 50 e8}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrueBot_PA_2147834001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrueBot.PA!MTB"
        threat_id = "2147834001"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrueBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%08x-%08x.ps1" ascii //weight: 1
        $x_1_2 = "n=%s&o=%s&a=%d&u=%s&p=%s&d=%s" ascii //weight: 1
        $x_3_3 = {33 c9 8b d9 8b 4d ?? 0f b6 d0 2a cb 8b 45 ?? 8b f2 88 0d ?? ?? ?? ?? 8b cf d3 e6 33 f2 0b 35 ?? ?? ?? ?? 03 c6 a3 ?? ?? ?? ?? e8}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

