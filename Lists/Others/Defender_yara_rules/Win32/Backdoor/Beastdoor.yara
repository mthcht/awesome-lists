rule Backdoor_Win32_Beastdoor_DQ_2147595290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Beastdoor.DQ"
        threat_id = "2147595290"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Beastdoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "150"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Beasty" ascii //weight: 100
        $x_10_2 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_10_3 = "Toolhelp32ReadProcessMemory" ascii //weight: 10
        $x_10_4 = "Process32First" ascii //weight: 10
        $x_5_5 = "ns1.ip-plus.net" ascii //weight: 5
        $x_5_6 = "GetScreen" ascii //weight: 5
        $x_5_7 = "GetWebCam" ascii //weight: 5
        $x_5_8 = "Shut Down:[" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Beastdoor_DS_2147596029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Beastdoor.DS"
        threat_id = "2147596029"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Beastdoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "===== Shut Down:[" ascii //weight: 3
        $x_3_2 = "Chat session started by" ascii //weight: 3
        $x_1_3 = "\\policies\\Explorer\\Run" ascii //weight: 1
        $x_1_4 = "SwapMouseButton" ascii //weight: 1
        $x_1_5 = "Toolhelp32ReadProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Beastdoor_DT_2147596030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Beastdoor.DT"
        threat_id = "2147596030"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Beastdoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "FIREFOX PASSWORDS" ascii //weight: 2
        $x_1_2 = "MozillaWindowClass" ascii //weight: 1
        $x_1_3 = "OpWindow" ascii //weight: 1
        $x_1_4 = "Opera Main Window" ascii //weight: 1
        $x_1_5 = "BEGIN CLIPBOARD" ascii //weight: 1
        $x_1_6 = "MAIL FROM:<" ascii //weight: 1
        $x_1_7 = "plain; charset=\"iso-8859" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Beastdoor_O_2147603606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Beastdoor.O"
        threat_id = "2147603606"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Beastdoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Passwd" ascii //weight: 1
        $x_1_2 = "Num Del" ascii //weight: 1
        $x_1_3 = "PgDn" ascii //weight: 1
        $x_1_4 = "Boot: [" ascii //weight: 1
        $x_10_5 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 a1 ?? ?? ?? ?? 8b 00 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02 a1 ?? ?? ?? ?? 50 a1 ?? ?? ?? ?? 50 a1 ?? ?? ?? ?? 50 a1 ?? ?? ?? ?? 8b 00 50 e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 00 50 e8 ?? ?? ?? ?? 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 a1 ?? ?? ?? ?? 8b 00 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02 a1 ?? ?? ?? ?? 80 38 00}  //weight: 10, accuracy: Low
        $x_10_6 = {53 56 57 55 83 c4 f8 ?? ?? ?? ?? 89 04 24 ?? ?? 8b 14 24 e8 ?? ?? ?? ?? ?? ?? 8b 45 00 e8 ?? ?? ?? ?? 66 85 c0 76 44 66 89 44 24 04 66 bb 01 00 ?? ?? e8 ?? ?? ?? ?? 0f b7 fb 8b 55 00 8a 54 3a ff 0f b7 ce c1 e9 08 32 d1 88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 69 c6 f1 aa 66 05 bd 54 ?? ?? 43 66 ff 4c 24 04 75 c5 59 5a 5d 5f 5e 5b c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Beastdoor_DU_2147606713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Beastdoor.DU"
        threat_id = "2147606713"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Beastdoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {c7 40 05 00 c8 00 00 a1 ?? ?? 41 00 c7 40 1a ?? ?? 00 00 a1 ?? ?? 41 00 c7 40 2f 60 30 00 00 a1 ?? ?? 41 00 c7 40 44 ?? ?? 00 00 a1 ?? ?? 41 00}  //weight: 3, accuracy: Low
        $x_3_2 = {75 15 81 fb 9a 02 00 00 74 0d 33 c0 5a 59 59 64 89 10 e9 ?? ?? 00 00 8b c3 83 f8 19 7f 7a 0f 84 ?? 08 00 00 83 f8 18 0f 87 ?? 09 00 00 ff 24 85 ?? ?? 40 00}  //weight: 3, accuracy: Low
        $x_1_3 = "keys.log" ascii //weight: 1
        $x_1_4 = "SAM\\A" ascii //weight: 1
        $x_1_5 = "\\shell\\open\\command" ascii //weight: 1
        $x_1_6 = "Hardware\\Description\\System\\CentralProcessor\\0" ascii //weight: 1
        $x_1_7 = "~~~~~~~~~~~~ Boot:[" ascii //weight: 1
        $x_1_8 = "*pass*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Beastdoor_S_2147626481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Beastdoor.S"
        threat_id = "2147626481"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Beastdoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d7 8b 4d fc 02 54 19 ff 88 54 18 ff 43 4e 75 e7}  //weight: 1, accuracy: High
        $x_1_2 = {88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 69 c6 f1 aa 66 05 bd 54 8b f0 43 66 ff 4c 24 04 75}  //weight: 1, accuracy: High
        $x_1_3 = {42 6f 6f 74 3a 20 5b 00 ff ff ff ff 03 00 00 00 5d 2d 5b 00}  //weight: 1, accuracy: High
        $x_1_4 = {7b 55 4e 44 4f 7d 00 00 ff ff ff ff 05 00 00 00 7b 54 41 42 7d 00}  //weight: 1, accuracy: High
        $x_1_5 = {41 49 4d 20 36 2e 78 00 ff ff ff ff 03 00 00 00 45 4e 44 00}  //weight: 1, accuracy: High
        $x_1_6 = {42 45 47 49 4e 20 43 4c 49 50 42 4f 41 52 44 [0-10] 45 4e 44 20 43 4c 49 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Beastdoor_P_2147627917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Beastdoor.P"
        threat_id = "2147627917"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Beastdoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 48 65 6c 70 5c [0-8] 2e 63 68 6d}  //weight: 1, accuracy: Low
        $x_1_2 = "|traffic|adult|pharma|partner|porno" ascii //weight: 1
        $x_1_3 = "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.1)" ascii //weight: 1
        $x_1_4 = {3a 32 30 38 32 0d 0a 3a 32 30 38 33 0d 0a 3a 32 30 38 36 0d 0a 3a 32 30 38 37}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

