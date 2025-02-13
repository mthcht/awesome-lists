rule Trojan_Win32_Disco_RE_2147842332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Disco.RE!MTB"
        threat_id = "2147842332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "domain := \"otsoserver.otso.space" ascii //weight: 1
        $x_1_2 = "ftplogin := \"56h74hnv" ascii //weight: 1
        $x_1_3 = "ftpassword := \"96475imh" ascii //weight: 1
        $x_1_4 = "FileAppend, %yarliksdata%, %A_AppData%\\Temporary\\yarliksdata.log" ascii //weight: 1
        $x_1_5 = "A_AppData \"\\Temporary\\shota.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Disco_RPX_2147888909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Disco.RPX!MTB"
        threat_id = "2147888909"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff d6 6a 00 6a 04 8d 84 24 7c 02 00 00 c7 84 24 7c 02 00 00 00 00 00 00 50 ff 74 24 44 53 ff d6 8b 84 24 74 02 00 00 8b 7c 24 3c 89 44 24 10 8b 84 24 7c 02 00 00 05 f4 00 00 00 c7 44 24 14 40 00 00 00 89 44 24 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Disco_GAA_2147898278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Disco.GAA!MTB"
        threat_id = "2147898278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 75 e8 8b 4d dc b8 ?? ?? ?? ?? 8b 7d d8 2b cf ff 85 ?? ?? ?? ?? 83 85 ?? ?? ?? ?? 18 f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 c2 39 85 ac fe ff ff 8b 85}  //weight: 10, accuracy: Low
        $x_1_2 = "discord.com/api/webhooks" ascii //weight: 1
        $x_1_3 = "\\discordcanary" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

