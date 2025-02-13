rule Backdoor_Win32_Nucleroot_A_2147583607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nucleroot.gen!A"
        threat_id = "2147583607"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nucleroot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {64 33 32 31 00 00 00 00 20 2d 39 20 72 6f 6f 74 6b 69 74 2e 65 78 65 00 75 70 78 2e 65 78 65 00 ff ff ff ff 13 00 00 00 4e 75 63 6c 65 61 72 20 52 6f 6f 74 6b 69 74 20 31 2e 30 00}  //weight: 2, accuracy: High
        $x_1_2 = {57 61 72 6e 69 6e 67 20 21 21 21 00 ff ff ff ff 29 00 00 00 54 68 65 20 52 6f 6f 74 6b 69 74 20 69 73 20 52 75 6e 6e 69 6e 67 20 6f 6e 20 59 6f 75 72 20 53 79 73 74 65 6d}  //weight: 1, accuracy: High
        $x_1_3 = {43 6f 6e 6e 65 63 74 69 6f 6e 20 48 69 64 65 00 ff ff ff ff 49 00 00 00 41 64 64 20 74 68 65 20 50 6f 72 74 20 2f 20 50 72 6f 74 6f 63 6f 6c 20 74 6f 20 48 69 64 65 20 74 68 65 20 43 6f 6e 6e 65 63 74 69 6f 6e 20 4f 6e 2f 74 68 72 6f 75 67 68 20 69 74 20 46 72 6f 6d 20 4e 65 74 73 74 61 74}  //weight: 1, accuracy: High
        $x_1_4 = {50 72 6f 63 65 73 73 20 48 69 64 65 00 00 00 00 ff ff ff ff 2b 00 00 00 41 64 64 20 54 68 65 20 50 72 6f 63 65 73 73 20 6e 61 6d 65 20 79 6f 75 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 6f 20}  //weight: 1, accuracy: High
        $x_1_5 = {46 69 6c 65 73 20 2f 20 44 69 72 73 20 20 48 69 64 65 00 00 ff ff ff ff 25 00 00 00 41 64 64 20 74 68 65 20 46 69 6c 65 20 6f 72 20 74 68 65 20 44 69 72 65 63 74 6f 72 79 20 74 6f 20 48 69 64 65}  //weight: 1, accuracy: High
        $x_2_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 00 00 ff ff ff ff 07 00 00 00 73 68 69 74 62 69 74}  //weight: 2, accuracy: High
        $x_2_7 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 00 00 00 63 3a 5c 77 6f 6f 74 2e 77 69 6e 6b}  //weight: 2, accuracy: High
        $x_2_8 = "rootkit.exe" ascii //weight: 2
        $x_2_9 = {08 00 00 00 6e 6b 69 74 2e 64 6c 6c}  //weight: 2, accuracy: High
        $x_1_10 = "svchos;smvs;smvs1;yingcang;yingcang1;fujia" ascii //weight: 1
        $x_1_11 = "FygTCleaner.exe;Trojanwall.exe;iparmor.exe;mmsk.exe;adam.exe;IceSword.exe;StartUpManager.exe;RmvTrjan.exe;ProcessJudger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Nucleroot_D_2147621345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nucleroot.D"
        threat_id = "2147621345"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nucleroot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 75 74 65 71 71 2e 63 6e 2f [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "http://www.cuteqq.cn/?from=" ascii //weight: 1
        $x_1_3 = ".ShellExecute(wwwcuteqqcn,' /c '+" ascii //weight: 1
        $x_1_4 = {89 4d fc c7 45 f8 ?? ?? ?? ?? c7 45 f4 ?? ?? ?? ?? c7 45 f0 ?? ?? ?? ?? c7 45 ec ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? 00 00 83 c4 08 89 45 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

