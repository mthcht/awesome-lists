rule Trojan_Win64_Winnti_A_2147689668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Winnti.A!dha"
        threat_id = "2147689668"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 89 5c 24 08 48 89 7c 24 10 48 63 d9 48 8d ?? ?? ?? ?? ?? 44 8b d2 48 c1 e3 06 80 e2 0f 41 c1 ea 04 44 0f b6 c2 0f b6 ca 41 80 e2 0f c0 e1 03 45 0f b6 ca 41 8b c1 49 33 c0 49 d1 e8 48 03 c3 49 0b c8 44 0f b6 1c 38 83 e1 0f 41 0f b6 c2 c0 e0 03 45 8b c3 49 33 c1 83 e0 0f 48 33 c8 48 03 cb 0f b6 44 39 10}  //weight: 5, accuracy: Low
        $x_5_2 = "q@3$%hy*&u" ascii //weight: 5
        $x_1_3 = "twofish" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Winnti_C_2147689685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Winnti.C!dha"
        threat_id = "2147689685"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RNTO" wide //weight: 1
        $x_1_2 = "XMD5" wide //weight: 1
        $x_1_3 = "Shell setup information:" wide //weight: 1
        $x_1_4 = "Uptime: %-.2d Days %-.2d Hours %-.2d Minutes %-.2d Seconds" wide //weight: 1
        $x_1_5 = "%s\\%d.log" wide //weight: 1
        $x_1_6 = "D:\\ZeusServer.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win64_Winnti_I_2147690225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Winnti.I!dha"
        threat_id = "2147690225"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pango-basic-win32.dll" ascii //weight: 1
        $x_1_2 = "tango.dll" ascii //weight: 1
        $x_1_3 = "%s\\%d%d.dat" ascii //weight: 1
        $x_1_4 = "%s\\sysprep\\cryptbase.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Winnti_I_2147690225_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Winnti.I!dha"
        threat_id = "2147690225"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pango-basic-win32.dll" ascii //weight: 1
        $x_1_2 = "tango.dll" ascii //weight: 1
        $x_1_3 = "%s\\%d%d.dat" ascii //weight: 1
        $x_1_4 = "%s\\sysprep\\cryptbase.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Winnti_H_2147690226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Winnti.H!dha"
        threat_id = "2147690226"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SHCreateItemFromParsingNam" ascii //weight: 10
        $x_10_2 = "otfkty.dat" ascii //weight: 10
        $x_1_3 = "work_start" ascii //weight: 1
        $x_1_4 = "work_end" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Winnti_H_2147690226_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Winnti.H!dha"
        threat_id = "2147690226"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SHCreateItemFromParsingNam" ascii //weight: 10
        $x_10_2 = "otfkty.dat" ascii //weight: 10
        $x_1_3 = "work_start" ascii //weight: 1
        $x_1_4 = "work_end" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Winnti_F_2147690227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Winnti.F!dha"
        threat_id = "2147690227"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\rundll32.exe \"%s\", DlgProc %s" ascii //weight: 1
        $x_1_2 = "AemaNeliFpmeTteG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Winnti_F_2147690227_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Winnti.F!dha"
        threat_id = "2147690227"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\rundll32.exe \"%s\", DlgProc %s" ascii //weight: 1
        $x_1_2 = "AemaNeliFpmeTteG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Winnti_J_2147692130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Winnti.J!dha"
        threat_id = "2147692130"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "Device\\PNTFILTER" wide //weight: 3
        $x_4_2 = {eb 53 48 8b 05 ?? ?? 00 00 8b 00 25 ff ff 00 00 3d b1 1d 00 00 73 0a c7 44 24 ?? 01 00 00 00 eb 08}  //weight: 4, accuracy: Low
        $x_1_3 = "Driver\\nsiproxy" wide //weight: 1
        $x_1_4 = "Device\\Tcp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Winnti_2147692925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Winnti!dha"
        threat_id = "2147692925"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%s\\sysprep\\cryptbase.dll" ascii //weight: 2
        $x_2_2 = "/oobe /quiet /quit" wide //weight: 2
        $x_2_3 = "Monitoring of Hardwares And Automatically Updates The Device Drivers" ascii //weight: 2
        $x_2_4 = "LookupAccountSidA" ascii //weight: 2
        $x_2_5 = "RUNAS" wide //weight: 2
        $x_2_6 = "wind0ws" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Winnti_G_2147694707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Winnti.G!dha"
        threat_id = "2147694707"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "userPassword" ascii //weight: 1
        $x_1_2 = "workdll64.dll" ascii //weight: 1
        $x_1_3 = "work_start" ascii //weight: 1
        $x_1_4 = "work_end" ascii //weight: 1
        $x_1_5 = "%s\\sysprep\\cryptbase.dll" ascii //weight: 1
        $x_1_6 = {2f 6c 6f 6f 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Winnti_K_2147696342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Winnti.K!dha"
        threat_id = "2147696342"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "work_end" ascii //weight: 1
        $x_1_2 = "work_start" ascii //weight: 1
        $x_1_3 = "GetAsyncKeyState" ascii //weight: 1
        $x_1_4 = "GetKeyState" ascii //weight: 1
        $x_1_5 = "[PageDown]" ascii //weight: 1
        $x_1_6 = "[Scroll Lock]" ascii //weight: 1
        $x_1_7 = {5b 46 31 5d 00 00 00 00 5b 45 53 43 5d 00}  //weight: 1, accuracy: High
        $x_1_8 = "Windows Title:%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Winnti_L_2147696571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Winnti.L!dha"
        threat_id = "2147696571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ProcessID=%d Plus=%s Ver=%d CmdId=%d Get Stuck" ascii //weight: 1
        $x_1_2 = "%s\\sysprep\\cryptbase.dll" ascii //weight: 1
        $x_1_3 = {77 6f 72 6b 5f 73 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {77 6f 72 6b 5f 65 6e 64 00}  //weight: 1, accuracy: High
        $x_1_5 = "net start IpFilterDriver" ascii //weight: 1
        $x_1_6 = "NtLoadDriver" ascii //weight: 1
        $x_1_7 = "advfirewall firewall add rule name=\"Windows Management Instrumentation (RPC-In)\" dir=in action=allow localport=%d protocol=TCP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win64_Winnti_M_2147705552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Winnti.M!dha"
        threat_id = "2147705552"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2d 6b 20 6e 65 74 73 76 63 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {25 73 5c 6c 70 6b 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {61 76 70 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = "/oobe /quiet /quit" wide //weight: 1
        $x_1_5 = "%s\\sysprep.exe" wide //weight: 1
        $x_1_6 = "%s\\sysprep\\cryptbase.dll" ascii //weight: 1
        $x_1_7 = {3a 74 72 79 0d 0a 64 65 6c 20 22 25 73 22 0d 0a 69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 74 72 79 0d 0a 64 65 6c 20 25 25 30}  //weight: 1, accuracy: High
        $x_1_8 = "wind0ws" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win64_Winnti_P_2147706284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Winnti.P!dha"
        threat_id = "2147706284"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {b0 99 41 83 fd 01 75 11 45 85 e4 7e 0c 30 07 48 ff c7 fe c0 48 ff cb 75 f4}  //weight: 10, accuracy: High
        $x_10_2 = {49 63 47 3c 48 8b 8c 24 c0 00 00 00 48 03 c3 33 d2 48 89 06 48 89 48 30 48 8b 06 0f b7 48 14 66 3b 50 06 0f 83 93 00 00 00 4c 8b ac 24 c8 00 00 00 48 8d 7c 01 28 8b 07 85 c0 75 35 49 63 44 24 38 85 c0 7e 5e 8b 4f fc 41 b9 40 00 00 00 41 b8 00 10 00 00 48 03 4e 08 48 8b d0 48 8b d8 41 ff d6 4c 8b c3 33 d2 48 8b c8 89 47 f8 41 ff d5 eb 32}  //weight: 10, accuracy: High
        $x_1_3 = "tango.dll" ascii //weight: 1
        $x_1_4 = {43 4f 4e 4e 45 43 54 20 25 73 3a 25 64 20 48 54 54 50 2f 31 2e 30 0d 0a 0d 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Winnti_N_2147711360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Winnti.N!dha"
        threat_id = "2147711360"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 0f b6 0b ff c2 49 ff c3 80 f1 36 0f b6 c1 c0 e9 04 c0 e0 04 02 c1 41 88 43 ff 3b 13 72 e1}  //weight: 1, accuracy: High
        $x_1_2 = {b9 03 14 20 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {b9 04 14 20 00 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = "Appinit64.dll" ascii //weight: 1
        $x_1_5 = {49 6e 73 74 61 6c 6c 00 54 65 73 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Winnti_T_2147717718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Winnti.T!dha"
        threat_id = "2147717718"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b1 99 75 15 33 c0 85 f6 7e 0f 8a 14 18 32 d1 fe c1 88 14 18 40 3b c6 7c f1}  //weight: 1, accuracy: High
        $x_2_2 = "aemanelifpmetteg" ascii //weight: 2
        $x_1_3 = {00 52 53 44 53}  //weight: 1, accuracy: High
        $x_1_4 = "%s\\rundll32.exe \"%s\", sql_init %s" ascii //weight: 1
        $x_1_5 = "%s\\rundll32.exe \"%s\", sqlite3_get_version %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Winnti_Y_2147741668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Winnti.Y!dha"
        threat_id = "2147741668"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 63 d0 43 8d 0c 01 41 ff c0 42 32 0c 1a 0f b6 c1 c0 e9 04 c0 e0 04 02 c1 42 88 04 1a 44 3b 03 72 de}  //weight: 1, accuracy: High
        $x_1_2 = {8b 0e 49 03 cc e8 ?? ?? ?? ?? 41 3b c5 74}  //weight: 1, accuracy: Low
        $x_1_3 = {69 c0 83 00 00 00 0f be d2 03 c2 48 ff c1 8a 11 84 d2 75 ec 0f ba f0 1f c3}  //weight: 1, accuracy: High
        $x_1_4 = {ff d8 ff e0 00 00 00 00 00 00 [0-100] e9 ea eb ec ed ee ef f0}  //weight: 1, accuracy: Low
        $x_1_5 = "stone64.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Winnti_Z_2147741669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Winnti.Z!dha"
        threat_id = "2147741669"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 0f b6 0b ff c2 49 ff c3 80 f1 36 0f b6 c1 c0 e9 04 c0 e0 04 02 c1 41 88 43 ff 3b ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 0e 49 03 cc e8 ?? ?? ?? ?? 41 3b c5 74}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 11 33 c0 84 d2 74 1c 0f 1f 80 00 00 00 00 69 c0 83 00 00 00 0f be d2 48 ff c1 03 c2 0f b6 11 84 d2}  //weight: 1, accuracy: High
        $x_1_4 = "Appinit64.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Winnti_ZA_2147741670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Winnti.ZA!dha"
        threat_id = "2147741670"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8a 1f b8 01 00 00 00 41 8d 0c 03 48 63 d0 ff c0 30 0c 3a 3b c3 72 f0 bb 3a 11 00 00 41 b9 40 00 00 00 41 b8 00 30 00 00 8b d3 33 c9 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = "g_thread_join" ascii //weight: 1
        $x_1_3 = "gthread-2.2.dll" ascii //weight: 1
        $x_1_4 = {63 6d 64 2e 65 78 65 20 2f 43 20 22 43 3a 5c 54 45 4d 50 5c [0-10] 2e 74 6d 70 2e 62 61 74 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Winnti_ZB_2147741671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Winnti.ZB!dha"
        threat_id = "2147741671"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b1 99 48 85 db 7e ?? 48 8b c7 30 08 40 02 ce 48 03 c6 48 2b de 75}  //weight: 1, accuracy: Low
        $x_1_2 = {48 83 64 24 30 00 45 33 c9 44 8b c6 ba 00 00 00 40 49 8b cd c7 44 24 28 80 00 00 00 c7 44 24 20 04 00 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {41 0f b6 11 41 ff c2 49 ff c1 80 f2 31 0f b6 c2 c0 ea 04 c0 e0 04 02 c2 41 88 41 ff 44 3b 56 0e 72}  //weight: 1, accuracy: High
        $x_1_4 = {ff d8 ff e0 00 00 00 00 00 00 [0-100] e9 ea eb ec ed ee ef f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Winnti_ZC_2147741672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Winnti.ZC!dha"
        threat_id = "2147741672"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 40 c0 80 00 00 00 44 8d 46 01 45 33 c9 ba 00 00 00 80 89 70 20 40 b7 99 c7 40 b8 04 00 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {40 30 3b 48 ff c3 40 fe c7 48 ff c9 75}  //weight: 1, accuracy: High
        $x_1_3 = "IISFilter64.dll" ascii //weight: 1
        $x_1_4 = "GetFilterVersion" ascii //weight: 1
        $x_1_5 = "HttpFilterProc" ascii //weight: 1
        $x_1_6 = "TerminateFilter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Winnti_SS_2147747980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Winnti.SS!MSRR"
        threat_id = "2147747980"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "MSRR: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "241B94-028A-441D-B9EB-B9AD3FDF0308" ascii //weight: 1
        $x_1_2 = "[Stone] Positive Login via 2K3 TCP, Res=" ascii //weight: 1
        $x_1_3 = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Winnti_SJ_2147748037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Winnti.SJ!dha"
        threat_id = "2147748037"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SplitNameAndHash failed" ascii //weight: 1
        $x_1_2 = "Credentials of new process has been changed" ascii //weight: 1
        $x_1_3 = "LUID:UserName:LogonDomain:LMhash:NThash" ascii //weight: 1
        $x_1_4 = "Reading by injecting code!" ascii //weight: 1
        $x_1_5 = "InjectMemDll err" ascii //weight: 1
        $x_1_6 = "GetPidByName %s ret err" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

