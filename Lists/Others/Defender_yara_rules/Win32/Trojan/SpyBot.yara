rule Trojan_Win32_SpyBot_G_2147749132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyBot.G!MTB"
        threat_id = "2147749132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 8d 0c 1f 8b c7 f7 75 18 8b 45 14 8a 04 02 32 04 0e 47 88 01 3b 7d 0c 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyBot_MR_2147753114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyBot.MR!MTB"
        threat_id = "2147753114"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {29 f6 2b 37 f7 de [0-10] c1 ce ?? 29 d6 83 ee ?? 29 d2 29 f2 f7 da c1 c2 ?? d1 ca 6a ?? 8f 01 01 31 83 e9 ?? 83 eb ?? 85 db 75}  //weight: 3, accuracy: Low
        $x_1_2 = "pncobjapi.dll" wide //weight: 1
        $x_1_3 = "pi.dll" wide //weight: 1
        $x_1_4 = "nddeapi.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SpyBot_DSK_2147753368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyBot.DSK!MTB"
        threat_id = "2147753368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 e4 03 45 fc 8b 4d ?? 8a 00 32 04 11 8b 4d e4 03 4d fc 88 01 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyBot_BZ_2147768568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyBot.BZ!MTB"
        threat_id = "2147768568"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "bgs/header.gif\" alt=\"SpyBot\">" ascii //weight: 1
        $x_1_2 = "spybot/css/screen.css\"/>" ascii //weight: 1
        $x_1_3 = "Spybot - Search & Destroy" wide //weight: 1
        $x_1_4 = "SDFSSvc.exe" wide //weight: 1
        $x_1_5 = {83 c4 08 b8 ?? ?? ?? ?? ff e0 8b e5 5d}  //weight: 1, accuracy: Low
        $x_1_6 = "eiorryub4j59yub935ny9v348ur89tvu3409r8vtu498r98" ascii //weight: 1
        $x_1_7 = "madCodeHook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

