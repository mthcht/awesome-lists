rule PWS_WinNT_OnLineGames_A_2147617424_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:WinNT/OnLineGames.A"
        threat_id = "2147617424"
        type = "PWS"
        platform = "WinNT: WinNT"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "koioiytghh99.sys" ascii //weight: 1
        $x_1_2 = {ff 55 bc 33 db 8d 85 7c ff ff ff 53 53 68 60 09 00 00 6a 01 6a 01 53 53 50}  //weight: 1, accuracy: High
        $x_1_3 = {39 5e 08 76 5e 53 e8 ?? ?? ff ff 8b 45 fc 8b 55 b8 8b c8 c1 e1 02 8b 84 0d 30 f2 ff ff 3b c2 76 37 8b 7d d4 03 fa 3b c7 73 2e 8b 3e 2b c2 53 8b 0c 39 8b f8 89 4d e8 e8 ?? ?? ff ff 03 7d f8 53 e8 58 fa ff ff 3b 7d e8 74 0e 53 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_WinNT_OnLineGames_D_2147656225_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:WinNT/OnLineGames.D"
        threat_id = "2147656225"
        type = "PWS"
        platform = "WinNT: WinNT"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 06 80 f1 ?? 88 08 40 4f 75 f4}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 34 70 81 fe 02 00 00 01 0f ?? ?? 01 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {f3 a6 74 18 bf ?? ?? ?? ?? 8d b5 ?? ?? ?? ?? 6a ?? 59 33 c0 f3 a6 0f}  //weight: 1, accuracy: Low
        $x_1_4 = {b9 00 80 00 00 33 c0 68 ?? ?? 01 00 f3 ab ff 35 ?? ?? ?? ?? 68 ?? ?? 01 00 e8 ?? ?? ff ff 85 c0 74}  //weight: 1, accuracy: Low
        $x_1_5 = {66 81 38 64 a1 75 27 66 81 78 06 8a 80 75 1f 0f b7 48 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_WinNT_OnLineGames_E_2147659131_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:WinNT/OnLineGames.E"
        threat_id = "2147659131"
        type = "PWS"
        platform = "WinNT: WinNT"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 00 1f 00 00 00 56 8b 01 03 c2 0f b6 50 03 0f b6 70 02}  //weight: 1, accuracy: High
        $x_1_2 = {8d 34 70 81 fe 02 00 00 01 0f}  //weight: 1, accuracy: High
        $x_1_3 = "wshtcpip.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_WinNT_OnLineGames_E_2147659131_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:WinNT/OnLineGames.E"
        threat_id = "2147659131"
        type = "PWS"
        platform = "WinNT: WinNT"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 00 4d c6 05 ?? ?? 01 00 41 c6 05 ?? ?? 01 00 50 c6 05 ?? ?? 01 00 44 c6 05 ?? ?? 01 00 4e c6 05 ?? ?? 01 00 46 c6 05 ?? ?? 01 00 77 c6 05 ?? ?? 01 00 77}  //weight: 1, accuracy: Low
        $x_1_2 = {01 00 56 c6 05 ?? ?? 01 00 33 c6 05 ?? ?? 01 00 41 c6 05 ?? ?? 01 00 56 c6 05 ?? ?? 01 00 56 c6 05 ?? ?? 01 00 33}  //weight: 1, accuracy: Low
        $x_1_3 = "MAPlestory.exe" ascii //weight: 1
        $x_1_4 = "V3ltray.exe" ascii //weight: 1
        $x_1_5 = "AVp.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

