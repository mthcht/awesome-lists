rule Backdoor_Win32_Prorat_AL_2147596025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Prorat.AL"
        threat_id = "2147596025"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Prorat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "331 Password required for %s." ascii //weight: 1
        $x_1_2 = "TCustomSmtpClient" ascii //weight: 1
        $x_1_3 = "MAIL FROM:<" ascii //weight: 1
        $x_1_4 = "TLNCL122,GZG" ascii //weight: 1
        $x_1_5 = "SOFTWARMirnPsofn\\etWinds NTTPrnipn" ascii //weight: 1
        $x_1_6 = "/// Outlook AaddresBook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Prorat_AM_2147596027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Prorat.AM"
        threat_id = "2147596027"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Prorat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "331 Password required for %s." ascii //weight: 1
        $x_1_2 = "TCustomSmtpClient" ascii //weight: 1
        $x_1_3 = "MAIL FROM:<" ascii //weight: 1
        $x_3_4 = "ProRat - Trojan Horse - Coded by" ascii //weight: 3
        $x_3_5 = "ProRat@Yahoo.Com" ascii //weight: 3
        $x_3_6 = "Dedected burute force atack" ascii //weight: 3
        $x_1_7 = "_ReadCdKeys" ascii //weight: 1
        $x_1_8 = "ICQ_UIN" ascii //weight: 1
        $x_1_9 = "/// URL HISTORY" ascii //weight: 1
        $x_1_10 = "Command=ToggleDesktop" ascii //weight: 1
        $x_1_11 = "User clicked: RETRY" ascii //weight: 1
        $x_1_12 = "Set cdaudio door" ascii //weight: 1
        $x_1_13 = "Victim name" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Prorat_AN_2147600479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Prorat.AN"
        threat_id = "2147600479"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Prorat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetWindowTextA" ascii //weight: 1
        $x_1_2 = "setWindowsHookExA" ascii //weight: 1
        $x_1_3 = {00 00 01 00 02 00 68 6f 64 6c 6c 2e 64 6c 6c 00 4b 49 49 73 53 65 73 5f 5f 4d 63 61 66 45 65 00 4b 69 73 73 65 73 5f 54 6f 5f 54 72 6f 6a 61 6e 68 75 6e 74 65 72 00 69 6e 73 74 61 6c 6c 68 6f 6f 6b 00 00 00 00 00 00 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\ktd32.atm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Prorat_AM_2147600666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Prorat.AM"
        threat_id = "2147600666"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Prorat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Trojan Horse - Coded by" ascii //weight: 1
        $x_1_2 = {2e 64 6c 6c 00 48 6f 6f 6b 50 72 6f 63 00 49 6e 73 74 61 6c 6c 48 6f 6f 6b 00 52 65 6d 6f 76 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Prorat_AZ_2147605018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Prorat.AZ"
        threat_id = "2147605018"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Prorat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "@[ProRat Trojan Horse - Coded by PRO Group - Made in Turkey]" ascii //weight: 1
        $x_1_2 = "ncom_." ascii //weight: 1
        $x_1_3 = "ncom.exe" ascii //weight: 1
        $x_1_4 = "if exist  %c%s%c goto 1" ascii //weight: 1
        $x_10_5 = {6a 00 52 55 ff 15 ?? ?? ?? ?? 8d 84 24 ?? ?? ?? ?? 50 6a 38 6a 37 6a 69 6a 6e 6a 69 6a 74 6a 6f 6a 66 e8 ?? ?? ?? ?? 8b f8 83 c4 30 8b cf 2b cb 8d 41 f2 85 c0 7e 25 8b d8 55}  //weight: 10, accuracy: Low
        $x_10_6 = {c1 e9 02 8b fa 8d 54 24 ?? f3 a5 8b c8 33 c0 83 e1 03 f3 a4 83 c9 ff bf ?? ?? ?? ?? f2 ae f7 d1 2b f9 8b f7 8b fa 8b d1 83 c9 ff f2 ae 8b ca 4f c1 e9 02 f3 a5 8b ca 8d 44 24 78 83 e1 03 a3 ?? ?? ?? ?? f3 a4 bf ?? ?? ?? ?? 83 c9 ff 33 c0 8d 54 24 ?? f2 ae f7 d1 2b f9 8b f7 8b fa 8b d1 83 c9 ff f2 ae 8b ca 4f c1 e9 02 f3 a5}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Prorat_AI_2147640492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Prorat.AI"
        threat_id = "2147640492"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Prorat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\_targetid" ascii //weight: 2
        $x_4_2 = "44C997F6EF8AE82E7053083E87EBE9245B" ascii //weight: 4
        $x_2_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\_loadname" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Prorat_BY_2147660392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Prorat.BY"
        threat_id = "2147660392"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Prorat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pc-rat.com" ascii //weight: 1
        $x_1_2 = "Kaspersky:avp.exe/KAVSvcUI.exe" ascii //weight: 1
        $x_1_3 = "Symantec Norton:ccapp.exe/ccevtmgr.exe" ascii //weight: 1
        $x_1_4 = "ESET NOD32:egui.exe/ekrn.exe" ascii //weight: 1
        $x_1_5 = "@members.3322.org/dyndns/update?system=dyndns&hostname=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

