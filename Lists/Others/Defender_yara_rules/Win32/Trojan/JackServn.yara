rule Trojan_Win32_JackServn_A_2147692361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/JackServn.A"
        threat_id = "2147692361"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "JackServn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 73 36 34 2e 64 6c 6c [0-5] 25 73 33 32 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_2 = "ServiceDownLoader" ascii //weight: 1
        $x_1_3 = "FINDWINDOW" ascii //weight: 1
        $x_1_4 = "HOOKDOWNLOADERDLL" ascii //weight: 1
        $x_1_5 = "REMOTESERVICENAME" ascii //weight: 1
        $x_1_6 = "WEBPATCHSERVER" ascii //weight: 1
        $x_1_7 = "WEBINIFILE" ascii //weight: 1
        $x_1_8 = "WEBFILESERVER" ascii //weight: 1
        $x_1_9 = {48 4f 4f 4b 4d 41 49 4e 44 4c 4c 00 48 4f 4f 4b}  //weight: 1, accuracy: High
        $x_1_10 = {00 54 41 52 47 45 54 41 50 50 00}  //weight: 1, accuracy: High
        $x_1_11 = {57 49 4e 50 43 41 50 00 4e 50 46}  //weight: 1, accuracy: High
        $x_1_12 = {46 49 4c 45 4e 41 4d 45 [0-16] 46 49 4c 45 4e 41 4d 45 [0-16] 46 49 4c 45 4e 41 4d 45 [0-16] 46 49 4c 45 4e 41 4d 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Trojan_Win32_JackServn_B_2147726335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/JackServn.B!bit"
        threat_id = "2147726335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "JackServn"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "E847761C2756D095E566F73C742E7FBF" ascii //weight: 1
        $x_1_2 = "%c%c%c%c%c%c%c%c%c%c" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "killfile.bat" ascii //weight: 1
        $x_1_5 = "%s\\svchost.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_JackServn_C_2147726814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/JackServn.C!bit"
        threat_id = "2147726814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "JackServn"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b1 2d 0f be c9 51 b1 5f 0f be d1 52 b1 77 0f be c9 51 0f be d3 52 b1 6e 0f be c9 51 b0 25 0f be c0 50 b1 2f 0f be d1 52 50 b0 65 0f be c0 50 b0 6d 0f be c8 b0 73 51 0f be d0 52 68 ?? ?? ?? 00 81 c6 1c 01 00 00 56 e8 ?? ?? ?? ff}  //weight: 2, accuracy: Low
        $x_2_2 = "D07F5871C889A088FDCABA9628003203" ascii //weight: 2
        $x_1_3 = "%c%c%c%c%c%c%c%c%c%c" ascii //weight: 1
        $x_1_4 = "killfile.bat" ascii //weight: 1
        $x_1_5 = "%s\\%s.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

