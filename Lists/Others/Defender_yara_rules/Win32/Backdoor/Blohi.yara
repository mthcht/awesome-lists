rule Backdoor_Win32_Blohi_A_2147652408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Blohi.gen!A"
        threat_id = "2147652408"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Blohi"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-s -f -t " wide //weight: 1
        $x_1_2 = "#ProcessL#" wide //weight: 1
        $x_1_3 = "Hacker --> " wide //weight: 1
        $x_1_4 = "#RemoteA#" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Blohi_B_2147655888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Blohi.gen!B"
        threat_id = "2147655888"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Blohi"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#ChatOK#" wide //weight: 1
        $x_1_2 = "c2h1dGRvd24gLXMgLWYgLXQgMA==" wide //weight: 1
        $x_1_3 = "SGFja2VyIC0tPiAg" wide //weight: 1
        $x_1_4 = "RG93bmxvYWQ=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Blohi_A_2147665126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Blohi.A"
        threat_id = "2147665126"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Blohi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "62"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 00 69 00 6e 00 48 00 74 00 74 00 70 00 2e 00 57 00 69 00 6e 00 48 00 74 00 74 00 70 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00 2e 00 35 00 2e 00 31 00 00 00}  //weight: 10, accuracy: High
        $x_10_2 = "noisreVDSC" wide //weight: 10
        $x_10_3 = {4a 00 75 00 6e 00 67 00 00 00}  //weight: 10, accuracy: High
        $x_10_4 = {59 00 6f 00 75 00 45 00 6e 00 64 00 00 00}  //weight: 10, accuracy: High
        $x_10_5 = {52 00 65 00 61 00 6c 00 45 00 6e 00 64 00 00 00}  //weight: 10, accuracy: High
        $x_10_6 = {73 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 20 00 2d 00 73 00 20 00 2d 00 66 00 20 00 2d 00 74 00 20 00 30 00 00 00}  //weight: 10, accuracy: High
        $x_1_7 = {54 00 43 00 50 00 20 00 44 00 61 00 74 00 61 00 20 00 46 00 6c 00 6f 00 6f 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = "UDP Trapic" wide //weight: 1
        $x_1_9 = "pds23.egloos.com/pds/201201/" wide //weight: 1
        $x_1_10 = {6d 00 74 00 70 00 2e 00 61 00 64 00 64 00 72 00 65 00 73 00 73 00 29 00 22 00 3e 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {22 00 20 00 3e 00 20 00 43 00 3a 00 5c 00 52 00 65 00 73 00 75 00 6c 00 74 00 2e 00 74 00 78 00 74 00 00 00 52 00 75 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_12 = {2f 00 6c 00 69 00 6e 00 6b 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_13 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6e 00 65 00 74 00 73 00 74 00 61 00 74 00 2e 00 65 00 78 00 65 00 00 00 18 00 00 00 5c 00 72 00 65 00 67 00 65 00 64 00 69 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_14 = {23 00 49 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 23 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Blohi_B_2147667185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Blohi.B"
        threat_id = "2147667185"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Blohi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "blog.naver.com/PostView.nhn" wide //weight: 1
        $x_1_2 = "Select * from AntiVirusProduct" wide //weight: 1
        $x_1_3 = "{Right Ctrl}" wide //weight: 1
        $x_2_4 = "sm=tab_hty.top&where=nexearch&ie=utf8&query=" wide //weight: 2
        $x_5_5 = "Internetal IExplore\"" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Blohi_C_2147667476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Blohi.gen!C"
        threat_id = "2147667476"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Blohi"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "blog.naver.com/PostView.nhn" wide //weight: 5
        $x_5_2 = "Internetal IExplore\"" wide //weight: 5
        $x_1_3 = {6a 56 51 ff d6 8d 55 ac 6a 4d 52 ff d6 8d 45 8c 6a 57 50 ff d6 8d 8d 6c ff ff ff 6a 41 51 ff d6 8d 95 4c ff ff ff 6a 52 52 ff d6 8d 85 2c ff ff ff 6a 45 50 ff d6}  //weight: 1, accuracy: High
        $x_1_4 = {6a 46 50 ff d6 8d 4d cc 6a 69 51 ff d6 8d 55 ac 6a 6c 52 ff d6 8d 45 8c 6a 65 50 ff d6 8d 8d 6c ff ff ff 6a 55 51 ff d6 8d 95 4c ff ff ff 6a 72}  //weight: 1, accuracy: High
        $x_1_5 = {66 72 6d 52 65 6d 6f 74 65 53 76 72 00}  //weight: 1, accuracy: High
        $x_1_6 = {53 74 6f 70 43 6c 69 65 6e 74 49 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Blohi_D_2147678959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Blohi.D"
        threat_id = "2147678959"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Blohi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" wide //weight: 1
        $x_1_2 = "WinHttp.WinHttpRequest.5" wide //weight: 1
        $x_1_3 = "\\FirewallPolicy\\StandardProfile /v \"DoNotAllowExceptions\" /t" wide //weight: 1
        $x_1_4 = "\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List /v " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

