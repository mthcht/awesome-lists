rule Backdoor_Win32_Qakbot_A_2147611136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Qakbot.A"
        threat_id = "2147611136"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "37"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://ijk.cc/cgi-bin/jl/jloader.pl?loadfile=q" ascii //weight: 10
        $x_10_2 = "Hello999W0rld777" ascii //weight: 10
        $x_10_3 = "_qbotnti.exe" ascii //weight: 10
        $x_5_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Runonce" ascii //weight: 5
        $x_5_5 = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Runonce" ascii //weight: 5
        $x_1_6 = "CreateRemoteThread" ascii //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Qakbot_B_2147611137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Qakbot.B"
        threat_id = "2147611137"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_qbotinj.exe" ascii //weight: 1
        $x_1_2 = "_qbot.dll" ascii //weight: 1
        $x_1_3 = "_qbotnti.exe" ascii //weight: 1
        $x_1_4 = "madway.net/u/updates" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_1_8 = "CreateMutexA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Qakbot_A_2147611138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Qakbot.gen!A"
        threat_id = "2147611138"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7d 29 8b 45 08 03 45 f8 0f be 08 8b 45 f8 99 f7 7d f0 0f be 82 ?? ?? ?? ?? 33 c8 88 4d fc 8b 45 08}  //weight: 2, accuracy: Low
        $x_2_2 = {7d 1f 8b 45 fc 99 f7 7d f4 8b 45 08 03 45 fc 8a 00 32 82 ?? ?? ?? ?? 8b 4d 08 03 4d fc 88 01 eb d2}  //weight: 2, accuracy: Low
        $x_2_3 = {75 0c c7 45 08 fd ff ff ff e9 67 01 00 00 56 68 00 04 00 00 68 ?? ?? ?? ?? ff 75 f8 53}  //weight: 2, accuracy: Low
        $x_2_4 = {e9 03 02 00 00 6a 00 68 00 04 00 00 68 ?? ?? ?? ?? ff 75 f4 ff b5}  //weight: 2, accuracy: Low
        $x_3_5 = "jl/jloader.pl?" ascii //weight: 3
        $x_1_6 = "%s\\%s.cb" ascii //weight: 1
        $x_1_7 = "%s\\%s.kcb" ascii //weight: 1
        $x_1_8 = "qbot_version=[%s]" ascii //weight: 1
        $x_1_9 = "Hello999W0rld777" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Qakbot_B_2147643209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Qakbot.gen!B"
        threat_id = "2147643209"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7d 49 80 a5 e8 fe ff ff 00 80 a5 fc fe ff ff 00 8b 45 08 03 85 f4 fe ff ff 0f be 08 8b 85 f4 fe ff ff 99 f7 bd ec fe ff ff 0f be 82 ?? ?? ?? ?? 33 c8 88 8d fc fe ff ff 8b 45 08}  //weight: 2, accuracy: Low
        $x_2_2 = {8d 46 5c 57 50 57 ff 56 54 3b c7 89 86 ?? ?? ?? ?? 75 0f 8b 46 58 3b c7 74 08 ff d0}  //weight: 2, accuracy: Low
        $x_2_3 = {74 70 8b 45 fc 6b c0 0c 8b 4d 08 8b 44 01 08 ff 34 85 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 89 45 f8}  //weight: 2, accuracy: Low
        $x_1_4 = "%s_%s_%u.kcb" ascii //weight: 1
        $x_1_5 = "%s\\%s_%u.cb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Qakbot_C_2147649364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Qakbot.gen!C"
        threat_id = "2147649364"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c8 81 e1 ff 00 00 00 8a 89 ?? ?? ?? ?? 30 88 ?? ?? ?? ?? 40 3d ?? ?? ?? ?? 72 e4}  //weight: 2, accuracy: Low
        $x_2_2 = {8d 46 5c 57 50 57 ff 56 54 3b c7 89 86 ?? ?? ?? ?? 75 0f 8b 46 58 3b c7 74 08 ff d0}  //weight: 2, accuracy: Low
        $x_2_3 = {74 63 8b f0 8b 40 08 ff 34 85 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 75 24}  //weight: 2, accuracy: Low
        $x_2_4 = {8a 54 05 fc 30 54 0d f4 40 83 f8 04}  //weight: 2, accuracy: High
        $x_1_5 = "&bg=%s&it=%u&salt=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Qakbot_T_2147688277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Qakbot.T"
        threat_id = "2147688277"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qbot_version=[%s]" ascii //weight: 1
        $x_1_2 = {00 75 70 64 62 6f 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 5f 71 62 6f 74 00}  //weight: 1, accuracy: High
        $x_1_4 = "%s_%s_%u.kcb" ascii //weight: 1
        $x_1_5 = "&n=%s&os=%s&bg=%s&it=%" ascii //weight: 1
        $x_1_6 = " user=[%s] pass=[%s]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Qakbot_T_2147688277_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Qakbot.T"
        threat_id = "2147688277"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cb 83 e1 3f 8a 89 ?? ?? ?? ?? 03 c3 30 08 75 0a 8b 4d fc 40 83 45 fc 04 89 01 43 81 fb ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {25 73 61 00 6f 6b 00 00 25 73 5c 25 64 2e 65 78 65 00 00 00 2f 63 20 22 25 73 22 00 25 73 25 73 00 00 00 00 61 00 00 00 44 6e 73 63 61 63 68 65}  //weight: 1, accuracy: High
        $x_1_3 = {43 3a 00 00 53 79 73 74 65 6d 44 72 69 76 65 00 54 45 4d 50 00}  //weight: 1, accuracy: High
        $x_1_4 = {25 73 64 62 67 5f 25 73 5f 25 75 5f 71 62 6f 74 64 6c 6c 2e 74 78 74 00 71 62 6f 74 5f 64 6c 6c 5f 6d 61 69 6e}  //weight: 1, accuracy: High
        $x_1_5 = "StopQbotThread(): waiting on szQbotRunMutex='%s'" ascii //weight: 1
        $x_1_6 = {8b 4d fc 8d 34 08 83 e1 3f 8a 89 ?? ?? ?? ?? 30 0e 75 0a 8b 4d f8 46 83 45 f8 04 89 31 ff 45 fc 81 7d fc ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Qakbot_T_2147688277_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Qakbot.T"
        threat_id = "2147688277"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qbot_version=[%s]" ascii //weight: 1
        $x_1_2 = {00 75 70 64 62 6f 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 5f 71 62 6f 74 00}  //weight: 1, accuracy: High
        $x_1_4 = "%s_%s_%u.kcb" ascii //weight: 1
        $x_1_5 = "&n=%s&os=%s&bg=%s&it=%" ascii //weight: 1
        $x_1_6 = " user=[%s] pass=[%s]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Qakbot_T_2147691741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Qakbot.T!!Qakbot.gen!A"
        threat_id = "2147691741"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "Qakbot: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qbot_version=[%s]" ascii //weight: 1
        $x_1_2 = {00 75 70 64 62 6f 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 5f 71 62 6f 74 00}  //weight: 1, accuracy: High
        $x_1_4 = "%s_%s_%u.kcb" ascii //weight: 1
        $x_1_5 = "&n=%s&os=%s&bg=%s&it=%" ascii //weight: 1
        $x_1_6 = " user=[%s] pass=[%s]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Qakbot_T_2147708643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Qakbot.T!gen"
        threat_id = "2147708643"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D:\\F9OuJSlU6cY\\o9bb\\c18L.xml" wide //weight: 1
        $x_1_2 = {4f 41 6e 50 76 51 76 58 49 78 4b 70 77 7a 62 00}  //weight: 1, accuracy: High
        $x_1_3 = {54 79 34 41 43 62 30 61 6a 4c 56 49 72 67 44 00}  //weight: 1, accuracy: High
        $x_1_4 = "X:\\58I7XTk1\\gaPJGDBpC\\7HAStPcS" wide //weight: 1
        $x_1_5 = {6e 39 45 4d 30 55 70 00}  //weight: 1, accuracy: High
        $x_5_6 = {04 0f b7 00 3d 4d 5a 00 00 74 02 eb}  //weight: 5, accuracy: High
        $x_2_7 = {00 70 ff d0 83 ec}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Qakbot_V_2147709390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Qakbot.V!bit"
        threat_id = "2147709390"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 0f 10 05 5c 40 00 70 f3 0f 10 0d 60 40 00 70 0f b6 05 24 ?? ?? ?? f3 0f 2a d0 f3 0f 59 d1 f3 0f 5e d0 0f b6 05 24 ?? ?? ?? f3 0f 11 14 85 dc ?? ?? ?? a0 24 ?? ?? ?? 04 01 a2 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Qakbot_W_2147726239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Qakbot.W"
        threat_id = "2147726239"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qbot_version=[%s]" ascii //weight: 1
        $x_1_2 = {00 5f 71 62 6f 74 00}  //weight: 1, accuracy: High
        $x_1_3 = " user=[%s] pass=[%s]" ascii //weight: 1
        $x_1_4 = "ext_ip=[%s] " ascii //weight: 1
        $x_1_5 = "dnsname=[%s] " ascii //weight: 1
        $x_1_6 = "hostname=[%s] " ascii //weight: 1
        $x_1_7 = "domain=[%s] " ascii //weight: 1
        $x_1_8 = "is_admin=[%s] " ascii //weight: 1
        $x_1_9 = "os=[%s] " ascii //weight: 1
        $x_1_10 = "install_time=[%s] " ascii //weight: 1
        $x_1_11 = "exe=[%s] " ascii //weight: 1
        $x_1_12 = "prod_id=[%s] " ascii //weight: 1
        $x_1_13 = "url=[%s] data=[%s]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Backdoor_Win32_Qakbot_Y_2147726240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Qakbot.Y"
        threat_id = "2147726240"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qbot_conf_path='%s' " ascii //weight: 1
        $x_1_2 = "dwErr=%u qbot_run_mutex='%s' username='%s'" ascii //weight: 1
        $x_1_3 = "%s%s/dupinst.php?n=%s&bg=%s&r=%u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

