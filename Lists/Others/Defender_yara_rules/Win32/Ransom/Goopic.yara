rule Ransom_Win32_Goopic_A_2147712640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Goopic.A"
        threat_id = "2147712640"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Goopic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\CurrentVersion\\GooglePic" ascii //weight: 1
        $x_1_2 = "\\Application Data\\service.exe" ascii //weight: 1
        $x_1_3 = {00 25 64 64 20 25 64 68 20 25 64 6d 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 21 7e 21 3f 21 7e 21 00}  //weight: 1, accuracy: High
        $x_2_5 = "WinHTTP BotName/1.0" ascii //weight: 2
        $x_1_6 = "Key received ! Decryption starting now ..." ascii //weight: 1
        $x_1_7 = "Your files was successfully decrypted !" ascii //weight: 1
        $x_1_8 = "Procedure complete!" ascii //weight: 1
        $x_1_9 = "delete shadows /all /quiet" ascii //weight: 1
        $x_1_10 = {00 6c 6f 63 6b 65 64 2f 00}  //weight: 1, accuracy: High
        $x_1_11 = "exodus99.ru" ascii //weight: 1
        $x_1_12 = {00 6f 75 74 2e 62 69 6e 00}  //weight: 1, accuracy: High
        $x_2_13 = "bd583ca6398a30758eef4525b8b91ed0625a43de" ascii //weight: 2
        $x_1_14 = {b8 64 6a 00 00}  //weight: 1, accuracy: High
        $x_2_15 = {6a 5a 68 00 08 00 00 ff ?? ff 15 ?? ?? ?? ?? ?? ?? ?? d3 4d 62 10}  //weight: 2, accuracy: Low
        $x_2_16 = {75 17 68 c0 27 09 00 c7 05 ?? ?? ?? ?? 01 00 00 00 ff 15 ?? ?? ?? ?? eb ce}  //weight: 2, accuracy: Low
        $x_3_17 = {ff d6 6a 05 6a 10 ff d7 50 6a 10 ff d7 50 ff 74 24 28 ff 74 24 28 6a ff ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff d6 68 60 ea 00 00 ff 15 ?? ?? ?? ?? e9 ?? ff ff ff}  //weight: 3, accuracy: Low
        $x_2_18 = "Your files have been crypted" ascii //weight: 2
        $x_1_19 = "InternetExplorer.Application" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Goopic_A_2147712641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Goopic.A!!Goopic.gen!A"
        threat_id = "2147712641"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Goopic"
        severity = "Critical"
        info = "Goopic: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\CurrentVersion\\GooglePic" ascii //weight: 1
        $x_1_2 = "\\Application Data\\service.exe" ascii //weight: 1
        $x_1_3 = {00 25 64 64 20 25 64 68 20 25 64 6d 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 21 7e 21 3f 21 7e 21 00}  //weight: 1, accuracy: High
        $x_2_5 = "WinHTTP BotName/1.0" ascii //weight: 2
        $x_1_6 = "Key received ! Decryption starting now ..." ascii //weight: 1
        $x_1_7 = "Your files was successfully decrypted !" ascii //weight: 1
        $x_1_8 = "Procedure complete!" ascii //weight: 1
        $x_1_9 = "delete shadows /all /quiet" ascii //weight: 1
        $x_1_10 = {00 6c 6f 63 6b 65 64 2f 00}  //weight: 1, accuracy: High
        $x_1_11 = "exodus99.ru" ascii //weight: 1
        $x_1_12 = "SELECT * FROM Win32_" ascii //weight: 1
        $x_1_13 = {00 6f 75 74 2e 62 69 6e 00}  //weight: 1, accuracy: High
        $x_2_14 = "bd583ca6398a30758eef4525b8b91ed0625a43de" ascii //weight: 2
        $x_2_15 = {b8 64 6a 00 00}  //weight: 2, accuracy: High
        $x_2_16 = {6a 5a 68 00 08 00 00 ff ?? ff 15 ?? ?? ?? ?? ?? ?? ?? d3 4d 62 10}  //weight: 2, accuracy: Low
        $x_2_17 = {75 17 68 c0 27 09 00 c7 05 ?? ?? ?? ?? 01 00 00 00 ff 15 ?? ?? ?? ?? eb ce}  //weight: 2, accuracy: Low
        $x_3_18 = {ff d6 6a 05 6a 10 ff d7 50 6a 10 ff d7 50 ff 74 24 28 ff 74 24 28 6a ff ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff d6 68 60 ea 00 00 ff 15 ?? ?? ?? ?? e9 ?? ff ff ff}  //weight: 3, accuracy: Low
        $x_2_19 = "Your files have been crypted" ascii //weight: 2
        $x_1_20 = "InternetExplorer.Application" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

