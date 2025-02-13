rule TrojanProxy_Win32_Horst_A_2147574313_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Horst.A"
        threat_id = "2147574313"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Horst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ws\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "CD-ECD2-23D0-BAC4-00DE" ascii //weight: 1
        $x_1_3 = "3645FBCD-ECD2-23D0-BAC4-00DE453DEF6" ascii //weight: 1
        $x_1_4 = ".nvsvcb" ascii //weight: 1
        $x_1_5 = "1.93" ascii //weight: 1
        $x_1_6 = {6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Horst_P_2147574433_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Horst.P"
        threat_id = "2147574433"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Horst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List" ascii //weight: 1
        $x_1_2 = "SAVScan" ascii //weight: 1
        $x_1_3 = "ec Core LC" ascii //weight: 1
        $x_1_4 = "Microsoft Update" ascii //weight: 1
        $x_1_5 = "KAVPersonal50" ascii //weight: 1
        $x_1_6 = "kavsvc" ascii //weight: 1
        $x_1_7 = "\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_8 = "SharedAccess" ascii //weight: 1
        $x_1_9 = "back.reznaz.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Horst_B_2147574442_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Horst.gen!B"
        threat_id = "2147574442"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Horst"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b c1 8b 88 00 08 00 00 33 d2 85 c9 7e 11 8b ff 80 34 02 07 8b 88 00 08 00 00 42 3b d1 7c f1 c3}  //weight: 3, accuracy: High
        $x_1_2 = "InternetReadFile" ascii //weight: 1
        $x_1_3 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_4 = "InternetOpenA" ascii //weight: 1
        $x_1_5 = "GetProcessPriorityBoost" ascii //weight: 1
        $x_1_6 = "GetProcessShutdownParameters" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Horst_C_2147575174_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Horst.gen!C"
        threat_id = "2147575174"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Horst"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "600"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {5d c3 8d 54 24 ?? 52 56 57 50 8b 44 24 ?? 50 ff 15 ?? ?? ?? ?? 85 c0 75 ?? [0-3] b8 04 00 00 00}  //weight: 100, accuracy: Low
        $x_100_2 = {5d c3 8d 54 24 ?? 52 57 56 50 8b 44 24 ?? 50 ff 15 ?? ?? ?? ?? 85 c0 75 ?? [0-3] b8 04 00 00 00}  //weight: 100, accuracy: Low
        $x_100_3 = {5d c3 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 10 8d 54 24 20 52 53 56 57 50 ff 15 ?? ?? ?? ?? 85 c0 75 0c b8 04 00 00 00 5f 5e 5b 8b e5 5d c3}  //weight: 100, accuracy: Low
        $x_100_4 = {5d c3 8b 54 24 ?? 8d 4c 24 ?? 51 57 56 50 52 ff 15 ?? ?? ?? ?? 85 c0 75 ?? 50 ff [0-6] b8 04 00 00 00}  //weight: 100, accuracy: Low
        $x_100_5 = {5d c3 8b 54 24 ?? 8d 4c 24 ?? 51 57 56 50 52 ff 15 ?? ?? ?? ?? 85 c0 75 ?? b8 04 00 00 00}  //weight: 100, accuracy: Low
        $x_100_6 = {c3 8d 54 24 ?? 52 53 57 50 8b 44 24 ?? 50 ff 15 ?? ?? ?? ?? 85 c0 75 0c b8 04 00 00 00}  //weight: 100, accuracy: Low
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_100_8 = {56 33 f6 46 39 35 ?? ?? ?? ?? 57 75 10 ff 75 08 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 83 7d 0c 00 8a 45 10}  //weight: 100, accuracy: Low
        $x_1_9 = "GetCurrentProcess" ascii //weight: 1
        $x_1_10 = "TerminateProcess" ascii //weight: 1
        $x_100_11 = {5d c3 8b 54 24 ?? 8b 45 ?? 8d 4c 24 ?? 51 52 89 84 24 ?? ?? 00 00 ff 15 ?? ?? ?? ?? 85 c0 75 ?? b8 06 00 00 00}  //weight: 100, accuracy: Low
        $x_100_12 = {5d c3 8b 4c 24 ?? 8b 55 ?? 8d 44 24 ?? 50 51 89 94 24 ?? ?? 00 00 ff 15 ?? ?? ?? ?? 85 c0 75 ?? b8 06 00 00 00}  //weight: 100, accuracy: Low
        $x_100_13 = {5d c3 8b 45 ?? 6a 01 89 84 24 ?? ?? 00 00 ff d6 8b 54 24 ?? 8d 4c 24 ?? 51 52 ff 15 ?? ?? ?? ?? 6a 01 8b f8 ff d6 85 ff 75 ?? b8 06 00 00 00}  //weight: 100, accuracy: Low
        $x_1_14 = "SetThreadContext" ascii //weight: 1
        $x_1_15 = "ResumeThread" ascii //weight: 1
        $x_100_16 = {55 8b ec 83 e4 f8 81 ec 18 08 00 00 8b 45 08 56 57 50 6a 00 6a 00 ff 15 ?? ?? ?? ?? 85 c0 75 2a 6a 03 8d 8c 24 18 04 00 00 e8 ?? ?? ?? ?? 8b f0 b9 03 01 00 00}  //weight: 100, accuracy: Low
        $x_100_17 = {55 8b ec 83 e4 f8 81 ec 18 08 00 00 8b 45 08 56 57 50 6a 00 6a 00 ff 15 ?? ?? ?? ?? [0-2] 8b f0 [0-6] 85 f6 75 2a 6a 03 8d 8c 24 18 04 00 00 e8 ?? ?? ?? ?? 8b f0 b9 03 01 00 00}  //weight: 100, accuracy: Low
        $x_1_18 = "OpenMutexA" ascii //weight: 1
        $x_1_19 = "CreateMutexA" ascii //weight: 1
        $x_100_20 = "svchost." ascii //weight: 100
        $x_1_21 = "wininet.dll" ascii //weight: 1
        $x_1_22 = "ws2_32.dll" ascii //weight: 1
        $x_100_23 = "3645FBCD-ECD2-23D0-BAC4" ascii //weight: 100
        $x_100_24 = "sdr0000-0001" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Horst_YA_2147594779_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Horst.YA"
        threat_id = "2147594779"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Horst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "javascript:top.parent.location='http://" ascii //weight: 1
        $x_1_2 = "Invalid Screen Name or Password. Please try again." wide //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ascii //weight: 1
        $x_1_4 = "Your message was not sent. Please click on the url below, complete the image puzzle, and then resend your message." wide //weight: 1
        $x_1_5 = "var bccList = [];" wide //weight: 1
        $x_1_6 = "var ccList = [];" wide //weight: 1
        $x_1_7 = "NoRemove" ascii //weight: 1
        $x_1_8 = "SendForm" ascii //weight: 1
        $x_1_9 = "loginId" ascii //weight: 1
        $x_1_10 = "http://www.aol.com/" ascii //weight: 1
        $x_1_11 = "Enter the characters in the image  below without any spaces:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule TrojanProxy_Win32_Horst_E_2147596677_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Horst.gen!E"
        threat_id = "2147596677"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Horst"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&Remember this answer" ascii //weight: 1
        $x_1_2 = "Warning: Components Have Changed" ascii //weight: 1
        $x_1_3 = "FirewallPolicy\\StandardProfile\\Authorized" ascii //weight: 1
        $x_1_4 = "%y%m%d%H%M%S.%." ascii //weight: 1
        $x_1_5 = "KAVPersonal50" ascii //weight: 1
        $x_1_6 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_7 = "Personal Firewall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanProxy_Win32_Horst_U_2147605076_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Horst.U"
        threat_id = "2147605076"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Horst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {85 c0 74 3c ff 15 ?? ?? ?? ?? c1 e8 0a 33 d2 b9 3c 00 00 00 f7 f1 50 ff 15 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 8b 55 08 52 e8 ?? ?? 00 00 83 c4 04 8b 4d 08 03 c8 51 ff 15 ?? ?? ?? ?? 83 c4 10}  //weight: 5, accuracy: Low
        $x_2_2 = "?get_tst=666" ascii //weight: 2
        $x_2_3 = "Host_ot_2101_" ascii //weight: 2
        $x_2_4 = "&randnumba=%d&uptime=%d" ascii //weight: 2
        $x_1_5 = "%127[0-9A-Za-z.]" ascii //weight: 1
        $x_1_6 = "%s:*:Enabled:ipsec" ascii //weight: 1
        $x_1_7 = "X-Forwarded-For: %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Horst_YC_2147606411_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Horst.YC"
        threat_id = "2147606411"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Horst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 18 50 6a ?? 68 ?? ?? ?? 00 8d 8d ?? ?? ff ff e8 ?? ?? ff ff 83 c0 18 50 6a 04 68 ?? ?? ?? 00 8d 8d ?? ?? ff ff e8 ?? ?? ff ff 83 c0 18 50 8d 85 ?? ?? ff ff 50}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 03 01 00 00 8b f0 8d bd ?? ?? ff ff f3 a5 68 ?? ?? ?? 00 8d ?? ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {0f be 4d 08 0f be 55 fe 33 ca 88 4d ff 6a 00 ff 15 ?? ?? ?? 00 6a 00 ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 55 0c 03 55 14 8a 02 88 45 fe 6a 00 ff 15 ?? ?? ?? 00 6a 00 ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanProxy_Win32_Horst_YD_2147606457_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Horst.YD"
        threat_id = "2147606457"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Horst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 10 8a ca 3a 17 75 1c 84 c9 74 14 8a 50 01 8a ca 3a 57 01 75 0e 83 c0 02 83 c7 02 84 c9 75 e0 33 c0 eb 05 1b c0}  //weight: 1, accuracy: High
        $x_1_2 = {8a 4f 01 47 84 c9 75 f8 8b c8 c1 e9 02 8b f2 f3 a5 8b c8 83 e1 03 6a 00 f3 a4 ff d5 6a 00 ff d5 6a 00 ff d5}  //weight: 1, accuracy: High
        $x_1_3 = {c7 44 24 10 30 75 00 00 ff d6 6a 00 ff d6 6a 00 ff d6 [0-32] 50 68 06 10 00 00 68 ff ff 00 00 57 ff d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanProxy_Win32_Horst_F_2147616047_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Horst.gen!F"
        threat_id = "2147616047"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Horst"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ECD2-23D0-BAC4-" ascii //weight: 1
        $x_1_2 = {2e 6e 76 73 76 63 ?? 00}  //weight: 1, accuracy: Low
        $x_1_3 = "ws\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = {25 73 00 6e 76 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

