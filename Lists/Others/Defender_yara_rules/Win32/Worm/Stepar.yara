rule Worm_Win32_Stepar_A_2147601634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Stepar.gen!A"
        threat_id = "2147601634"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Stepar"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f3 a5 89 44 24 5c 89 44 24 70 89 44 24 74 89 44 24 78 89 44 24 7c 8d 44 24 10 50 68 3f 00 0f 00 8d 8c 24 20 01 00 00 6a 00 51 68 02 00 00 80 66 a5 c7 44 24 4c 00 00 ?? ?? c7 44 24 50 00 00 ?? ?? c7 44 24 54 00 00 ?? ?? c7 44 24 58 00 00 ?? ?? c7 44 24 5c 00 00 ?? ?? c7 44 24 60 00 00 ?? ?? c7 44 24 64 00 00 ?? ?? c7 44 24 68 00 00 ?? ?? c7 44 24 6c 00 00 ?? ?? c7 44 24 74 00 00 ?? ?? c7 44 24 78 00 00 ?? ?? c7 44 24 7c 00 00 ?? ?? c7 84 24 80 00 00 00 00 00 ?? ?? ff d3}  //weight: 2, accuracy: Low
        $x_2_2 = {8d 4c 24 20 c6 44 24 20 57 c6 44 24 21 49 68 00 00 22 10 51 c6 44 24 2a 4e ff d6 8d 94 24 98 00 00 00 68 ?? ?? ?? ?? 52 ff d6}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 4c 24 0c 6a 21 68 21 4e 00 00 51 50 ff 15 ?? ?? ?? ?? 5f 33 c0 5e c2 10 00}  //weight: 2, accuracy: Low
        $x_1_4 = "<iframe src=3Dcid:%s height=3D0 width=3D0>" ascii //weight: 1
        $x_1_5 = "Content-Type: application/octet-stream; name=\"%s\"" ascii //weight: 1
        $x_1_6 = "MozillaWindowClass" ascii //weight: 1
        $x_1_7 = "Outlook Express Browser Class" ascii //weight: 1
        $x_1_8 = "TMailerForm" ascii //weight: 1
        $x_1_9 = "DownloadDir" ascii //weight: 1
        $x_1_10 = "System Recovery Agent" ascii //weight: 1
        $x_1_11 = "Software\\Kazaa\\LocalContent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Stepar_B_2147624279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Stepar.gen!B"
        threat_id = "2147624279"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Stepar"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f3 a5 89 44 24 5c 89 44 24 70 89 44 24 74 89 44 24 78 89 44 24 7c 8d 44 24 10 50 68 3f 00 0f 00 8d 8c 24 20 01 00 00 6a 00 51 68 02 00 00 80 66 a5 c7 44 24 4c ?? ?? ?? ?? c7 44 24 50 ?? ?? ?? ?? c7 44 24 54 ?? ?? ?? ?? c7 44 24 58 ?? ?? ?? ?? c7 44 24 5c ?? ?? ?? ?? c7 44 24 60 ?? ?? ?? ?? c7 44 24 64 ?? ?? ?? ?? c7 44 24 68 ?? ?? ?? ?? c7 44 24 6c ?? ?? ?? ?? c7 44 24 74 ?? ?? ?? ?? c7 44 24 78 ?? ?? ?? ?? c7 44 24 7c ?? ?? ?? ?? c7 84 24 80 00 00 00 ?? ?? ?? ?? ff d3}  //weight: 2, accuracy: Low
        $x_2_2 = {8d 4c 24 20 c6 44 24 20 57 c6 44 24 21 49 68 ?? ?? ?? ?? 51 c6 44 24 2a 4e ff d6 8d 94 24 98 00 00 00 68 ?? ?? ?? ?? 52 ff d6}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 4c 24 0c 6a 21 68 21 4e 00 00 51 50 ff 15 ?? ?? ?? ?? 5f 33 c0 5e c2 10 00}  //weight: 2, accuracy: Low
        $x_1_4 = "<iframe src=3Dcid:%s height=3D0 width=3D0>" ascii //weight: 1
        $x_1_5 = "Content-Type: application/octet-stream; name=\"%s\"" ascii //weight: 1
        $x_1_6 = "MozillaWindowClass" ascii //weight: 1
        $x_1_7 = "Outlook Express Browser Class" ascii //weight: 1
        $x_1_8 = "TMailerForm" ascii //weight: 1
        $x_1_9 = "DownloadDir" ascii //weight: 1
        $x_1_10 = "System Recovery Agent" ascii //weight: 1
        $x_1_11 = "Software\\Kazaa\\LocalContent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

