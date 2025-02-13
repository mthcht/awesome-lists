rule Backdoor_Win32_Phorpiex_J_2147729748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Phorpiex.J"
        threat_id = "2147729748"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {51 8b c1 b9 08 00 00 00 8b d0 83 e2 01 75 04 d1 e8 eb 07 d1 e8 35 ?? ?? ?? ?? e2 ec ab 59 41 81 f9 00 01 00 00 72 d9 8b 75 08 8b 7d 0c 33 c9 bb ff ff ff ff 51 33 c0 ac 8b d3 c1 eb 08 53 87 d3 81 e3 ff 00 00 00 33 d8 93 b9 04 00 00 00 f7 e1 93 8b ?? ?? 03 c3 8b 00 5b 33 c3 8b d8 59 41 3b cf 72 d1}  //weight: 20, accuracy: Low
        $x_20_2 = {b8 04 04 04 04 8d 7d ?? aa 83 7d ?? ?? 74 06 83 7d ?? ?? 75 ?? 8a 45 ?? 8d 7d ?? 66 0f b6 c8 66 c1 e0 08 66 0b c1 aa eb ?? b8 01 01 01 01 8d 7d ?? aa}  //weight: 20, accuracy: Low
        $x_5_3 = "92.63.197.48" ascii //weight: 5
        $x_5_4 = "WINDOWS\\T-405068694930305840" ascii //weight: 5
        $x_5_5 = "%temp%\\495050583930.exe&start %temp%\\495050583930.exe" ascii //weight: 5
        $x_5_6 = "PowerShell -ExecutionPolicy Bypass (New-Object System.Net.WebClient).DownloadFile" ascii //weight: 5
        $x_5_7 = "bitsadmin /transfer getitman /download /priority high" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_5_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Phorpiex_YO_2147730070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Phorpiex.YO!MTB"
        threat_id = "2147730070"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PowerShell -ExecutionPolicy Bypass (New-Object System.Net.WebClient).DownloadFile" ascii //weight: 1
        $x_1_2 = "bitsadmin /transfer" ascii //weight: 1
        $x_1_3 = "start %temp%\\" ascii //weight: 1
        $x_1_4 = "vboxtray.exe" ascii //weight: 1
        $x_1_5 = "Passwort" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Phorpiex_YP_2147735877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Phorpiex.YP!bit"
        threat_id = "2147735877"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%ls\\%d%d%d%d.jpg" wide //weight: 1
        $x_1_2 = "t%ls%d.txt" wide //weight: 1
        $x_1_3 = "Received: (qmail %s invoked by uid %s)" ascii //weight: 1
        $x_1_4 = "%s, %u %s %u %.2u:%.2u:%.2u %s%.2u%.2u" ascii //weight: 1
        $x_1_5 = "infected" ascii //weight: 1
        $x_1_6 = "bitcoin" ascii //weight: 1
        $x_1_7 = {99 b9 10 27 00 00 f7 f9 81 c2 e8 03 00 00 52 e8 ?? ?? ?? ?? 99 b9 10 27 00 00 f7 f9 81 c2 e8 03 00 00 52 8d 95 ?? ?? ?? ?? 52 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Phorpiex_YA_2147740829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Phorpiex.YA!MTB"
        threat_id = "2147740829"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "I can ruin your life" ascii //weight: 1
        $x_1_2 = "I got all your data" ascii //weight: 1
        $x_1_3 = "I recorded you" ascii //weight: 1
        $x_1_4 = "You got recorded" ascii //weight: 1
        $x_1_5 = "I can publish everything" ascii //weight: 1
        $x_1_6 = "You dirty pervert" ascii //weight: 1
        $x_1_7 = "You got infected" ascii //weight: 1
        $x_1_8 = "Your computer infected" ascii //weight: 1
        $x_1_9 = "Stop mastrubate" ascii //weight: 1
        $x_1_10 = "Recorded you mastrubating" ascii //weight: 1
        $x_1_11 = "Video of you mastrubating" ascii //weight: 1
        $x_1_12 = "Better pay me" ascii //weight: 1
        $x_1_13 = "Don't ignore this mail" ascii //weight: 1
        $x_1_14 = "Recorded you" ascii //weight: 1
        $x_1_15 = "Stop watching porn" ascii //weight: 1
        $x_1_16 = "Stop visit porn sites" ascii //weight: 1
        $x_1_17 = "I know your password" ascii //weight: 1
        $x_1_18 = "I got video of you" ascii //weight: 1
        $x_1_19 = "Seen you mastrubating" ascii //weight: 1
        $x_1_20 = "I know everything about you" ascii //weight: 1
        $x_1_21 = "Chance to save your life" ascii //weight: 1
        $x_1_22 = "I won't ask again" ascii //weight: 1
        $x_1_23 = "I won't warn you again" ascii //weight: 1
        $x_1_24 = "Save your ass" ascii //weight: 1
        $x_25_25 = "%ls\\%d%d%d%d.jpg" wide //weight: 25
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_25_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

