rule Backdoor_Win32_Tofsee_A_2147595467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.A"
        threat_id = "2147595467"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CurrentVersion\\WinSetup" ascii //weight: 1
        $x_1_2 = "Referer: http://%s%s" ascii //weight: 1
        $x_2_3 = "{display:none}" ascii //weight: 2
        $x_1_4 = "http://%s:%d/%s" ascii //weight: 1
        $x_1_5 = "__RR_BOT__" ascii //weight: 1
        $x_2_6 = "netsh firewall set allowedprogram %s enable" ascii //weight: 2
        $x_2_7 = {81 7c 24 24 aa aa aa aa 59 59}  //weight: 2, accuracy: High
        $x_2_8 = {6f 6d 61 69 6e 3d 00 00 0d 0a 4c 6f 63 61 74 69}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Tofsee_B_2147597508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.B"
        threat_id = "2147597508"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fb: sub='%s'" ascii //weight: 1
        $x_1_2 = "fb: s='%s'" ascii //weight: 1
        $x_1_3 = "fb: presence='%s'" ascii //weight: 1
        $x_1_4 = "fb: p='%s'" ascii //weight: 1
        $x_1_5 = "fb: lu='%s'" ascii //weight: 1
        $x_1_6 = "fb: fr='%s'" ascii //weight: 1
        $x_1_7 = "fb: datr='%s'" ascii //weight: 1
        $x_1_8 = "fb: xs='%s'" ascii //weight: 1
        $x_1_9 = "fb: c_user='%s'" ascii //weight: 1
        $x_1_10 = "fb: IE found" ascii //weight: 1
        $x_1_11 = "facebook.com" ascii //weight: 1
        $x_1_12 = "TW %s perr" ascii //weight: 1
        $x_1_13 = "TW %s priv" ascii //weight: 1
        $x_1_14 = "TW %s recp" ascii //weight: 1
        $x_1_15 = "TW %s cook" ascii //weight: 1
        $x_1_16 = "TW %s mobi" ascii //weight: 1
        $x_1_17 = "TW %s open" ascii //weight: 1
        $x_1_18 = "TW %s call" ascii //weight: 1
        $x_1_19 = ".twitter.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Tofsee_B_2147597508_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.B"
        threat_id = "2147597508"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 85 58 ff ff ff 50 ff 75 f4 be ?? ?? ?? 00 89 5d b0 89 5d b4 89 75 a8 89 5d ac ff 15 ?? ?? 40 00 85 c0 0f 8c ?? 02 00 00 53 8d 45 b0 50 56 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Tofsee_B_2147597509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.B!sys"
        threat_id = "2147597509"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 68 8d 84 3d ?? eb ff ff 80 78 ff 32 75 56 80 38 35 75 51 80 78 01 30 75 4b ff 75 ?? 8d 85 ?? ff ff ff 50 8d 4d ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {74 1a 83 ce ff 8d 0c 06 8a 8c 0d e0 fe ff ff 80 f1 c5 48 88 8c 06 ?? ?? 40 00 75 e9 33 c0 89 45 fc 8d 45 f8 50 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win32_Tofsee_C_2147598309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.C"
        threat_id = "2147598309"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Plugin restarted" ascii //weight: 1
        $x_1_2 = "localcfg" ascii //weight: 1
        $x_1_3 = "USB errs" ascii //weight: 1
        $x_1_4 = "USB sccs" ascii //weight: 1
        $x_1_5 = "USB drvs" ascii //weight: 1
        $x_1_6 = "usb: done" ascii //weight: 1
        $x_1_7 = "[autorun]" ascii //weight: 1
        $x_1_8 = "shellexecute=" ascii //weight: 1
        $x_1_9 = "RECYCLER" ascii //weight: 1
        $x_1_10 = "usb: Drive '%s' found" ascii //weight: 1
        $x_1_11 = "autorun.inf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Tofsee_E_2147602530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.E"
        threat_id = "2147602530"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 3a 5c 73 70 62 6f 74 2e 6c 6f 67 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {69 70 20 69 6e 20 62 6c 61 63 6b 20 6c 69 73 74 20 28 6f 72 20 48 45 4c 4f 20 69 73 20 62 61 64 29 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 70 62 6f 74 20 2d 3e 20 28 25 64 3a 25 64 3a 25 64 29 20 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 25 69 25 69 25 69 32 6c 64 2e 65 78 65 00 00 25 64 00 00 53 4f 46 54 57}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Tofsee_F_2147603588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.F"
        threat_id = "2147603588"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 54 24 04 8b 44 24 08 53 56 b3 ?? 8d 34 02 eb 14 0f b6 0a 8b c1 c1 e8 03 c0 e1 05 0a c1 32 c3 88 02 8a d8 42 3b d6 72 e8}  //weight: 4, accuracy: Low
        $x_4_2 = {8b 4c 24 04 8b 54 24 08 56 b0 ?? 8d 34 11 eb 14 30 01 0f b6 11 8b c2 c1 e8 05 c0 e2 03 0a c2 88 01 34 c6 41 3b ce 72 e8}  //weight: 4, accuracy: Low
        $x_2_3 = {5f 5f 52 52 5f 42 4f 54 5f 5f 00}  //weight: 2, accuracy: High
        $x_1_4 = {5f 50 41 53 53 57 44 5f 00}  //weight: 1, accuracy: High
        $x_1_5 = {5f 41 43 43 5f 00}  //weight: 1, accuracy: High
        $x_1_6 = {68 74 74 70 25 73 3a 2f 2f 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Tofsee_B_2147609678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.gen!B"
        threat_id = "2147609678"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c6 45 f3 a5 8b 45 08 89 45 fc 8b 4d fc 03 4d 0c 89 4d f4 8b 55 fc 3b 55 f4 73 ?? 8b 45 fc 0f b6 08 89 4d f8 8b 55 f8 c1 e2 08 0b 55 f8 c1 ea 03 81 e2 ff 00 00 00 8b 45 fc 88 10}  //weight: 5, accuracy: Low
        $x_3_2 = {67 68 65 67 64 6a 66 00}  //weight: 3, accuracy: High
        $x_1_3 = "netsh firewall set allowedprogram \"%s\" ENABLE" ascii //weight: 1
        $x_1_4 = {5f 50 41 53 53 57 44 5f 00}  //weight: 1, accuracy: High
        $x_1_5 = {5f 41 43 43 5f 00}  //weight: 1, accuracy: High
        $x_1_6 = {68 74 74 70 25 73 3a 2f 2f 25 73 25 73 25 73 25 73 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Tofsee_I_2147621082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.I"
        threat_id = "2147621082"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8a 14 06 32 55 14 88 10 8a d1 02 55 18 f6 d9 00 55 14 40 4f 75 ea}  //weight: 4, accuracy: High
        $x_4_2 = {76 0f 8b 44 24 04 03 c1 f6 10 41 3b 4c 24 08 72 f1 c3}  //weight: 4, accuracy: High
        $x_1_3 = {59 59 7f 12 46 8b c6 c1 e0 03 8d 88 ?? ?? ?? ?? 39 19 75 c1 eb 0e}  //weight: 1, accuracy: Low
        $x_1_4 = "secupdat.dat" ascii //weight: 1
        $x_1_5 = "\\\\.\\rotcetorp" wide //weight: 1
        $x_1_6 = {83 f8 0e 7d 1e 0f b6 80 ?? ?? ?? ?? 83 e8 00 74 36 48 74 29 48 74 1c 48 74 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Tofsee_J_2147625810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.J"
        threat_id = "2147625810"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 00 32 00 50 00 48 00 45 00 4c 00 50 00 2e 00 49 00 43 00 4f 00 09 00 53 00 48 00 49 00 54 00 2e 00 53 00 48 00 49 00 54 00 28 00 00 00 10 00 00 00 20 00 00 00 01 00 04 00 00 00 00 00 c0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 80 80 00 80 00 00 00 80 00 80 00 80 80 00 00 c0 c0 c0 00 80 80 80 00 00 00 ff 00 00 ff 00 00 00 ff ff 00 ff 00 00 00 ff 00 ff 00 ff ff 00 00 ff ff ff 00 11 11 10 00 00 01 11 11 11 10 0b bb bb b0 01 11 11 0b bb bb bb bb b0 11 10 bb bb b0 0b bb bb 01 10 bb bb 0f f0 bb bb 01 0b bb b0 ff ff 0b bb b0 0b bb 00 ff ff 00 bb b0 0b bb bb 0f f0 bb bb b0 0b bb bb 0f f0 bb bb b0 0b bb bb 0f f0 bb bb b0 0b bb bb 0f f0 bb bb b0 10 bb bb 0f f0 bb bb 01 10 bb bb 00 00 bb bb 01 11 0b bb bb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Tofsee_T_2147683703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.T"
        threat_id = "2147683703"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 99 f7 f9 6a 0a 04 30 88 06 8b c1 8b fa 99 59 f7 f9 46 8b c8 85 c9 75 e6}  //weight: 1, accuracy: High
        $x_1_2 = {80 3f 5b 75 2e 47 40 57 89 06 e8 ?? ?? ?? ?? 59 89 45 fc eb 07 3c 39}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 7e 04 8d 87 88 00 00 00 c7 46 08 88 00 00 00 8b 5e 08 50 c7 46 0c 84 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {8a 4c 06 14 80 f9 44 74 12 80 f9 51 74 0d}  //weight: 1, accuracy: High
        $x_1_5 = "%04x%08.8lx$%08.8lx$%08x@%s" ascii //weight: 1
        $x_1_6 = "%P5DATE" ascii //weight: 1
        $x_1_7 = "%FROM_EMAIL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Tofsee_A_2147689643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.A!dll"
        threat_id = "2147689643"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 61 6e 74 69 62 6f 74 2e 64 6c 6c 00 70 6c 67 5f 69 6e 69 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 64 64 6f 73 52 2e 64 6c 6c 00 70 6c 67 5f 69 6e 69 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 6c 6f 63 73 52 2e 64 6c 6c 00 70 6c 67 5f 69 6e 69 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 6d 69 6e 65 72 2e 64 6c 6c 00 70 6c 67 5f 69 6e 69 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 70 72 6f 74 65 63 74 2e 64 6c 6c 00 70 6c 67 5f 69 6e 69 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 70 72 6f 78 79 52 2e 64 6c 6c 00 70 6c 67 5f 69 6e 69 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 73 6d 74 70 2e 64 6c 6c 00 70 6c 67 5f 69 6e 69 74 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 73 6e 72 70 52 2e 64 6c 6c 00 70 6c 67 5f 69 6e 69 74 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 73 70 72 65 61 64 31 2e 64 6c 6c 00 70 6c 67 5f 69 6e 69 74 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 73 70 72 65 61 64 32 2e 64 6c 6c 00 70 6c 67 5f 69 6e 69 74 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 73 79 73 2e 64 6c 6c 00 70 6c 67 5f 69 6e 69 74 00}  //weight: 1, accuracy: High
        $x_1_12 = {00 74 65 78 74 2e 64 6c 6c 00 70 6c 67 5f 69 6e 69 74 00}  //weight: 1, accuracy: High
        $x_1_13 = {00 77 65 62 62 2e 64 6c 6c 00 70 6c 67 5f 69 6e 69 74 00}  //weight: 1, accuracy: High
        $x_1_14 = {00 66 62 72 69 64 67 00 70 6c 67 5f 69 6e 69 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win32_Tofsee_BD_2147749096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.BD!MTB"
        threat_id = "2147749096"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f7 c1 ee 05 03 74 24 ?? 03 ?? 03 ?? 33 ?? 81 3d ?? ?? ?? ?? 72 07 00 00 75 1b 00 56 ff 15 ?? ?? ?? ?? 8b ?? 24 ?? 8b ?? 24 ?? 89 35 ?? ?? ?? ?? 89 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Tofsee_BD_2147749096_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.BD!MTB"
        threat_id = "2147749096"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c1 03 05 ?? ?? ?? ?? 25 ff 00 00 00 8a ?? ?? ?? ?? ?? 88 88 ?? ?? ?? ?? 88 96 ?? ?? ?? ?? 0f b6 b0 ?? ?? ?? ?? 0f b6 ca 03 f1 81 e6 ff 00 00 00 81 3d ?? ?? ?? ?? 81 0c 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {30 06 83 6c 24 ?? 01 8b 44 24 ?? 85 c0 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Tofsee_BS_2147750357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.BS!MTB"
        threat_id = "2147750357"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d 08 30 04 0e 46 3b 75 0c 7c ?? 5f 5e 5b 8b e5 5d c2 08 00}  //weight: 2, accuracy: Low
        $x_1_2 = {8b c7 c1 e8 05 03 44 24 38 03 d7 33 ca 81 3d ?? ?? ?? ?? 72 07 00 00 89 1d ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_3 = {8b fd d3 e7 8b f5 c1 ee 05 03 74 24 28 03 7c 24 2c 03 c5 33 f8 81 3d ?? ?? ?? ?? b4 11 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Tofsee_KM_2147751761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.KM!MTB"
        threat_id = "2147751761"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 83 c0 7b 89 45 fc b8 f9 cd 03 00 01 45 fc 83 6d fc 7b 8b 45 fc 8a 04 08 88 04 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Tofsee_KM_2147751761_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.KM!MTB"
        threat_id = "2147751761"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e2 89 5c 24 ?? 89 54 24 ?? 8b 44 24 ?? ?? 44 24 0c 8b 44 24 ?? ?? 44 24 0c 8b 44 24 ?? 8b 0d ?? ?? ?? ?? 03 c6 81 f9 72 05 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Tofsee_BC_2147752178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.BC!MTB"
        threat_id = "2147752178"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cb 03 d3 c1 e9 05 03 8d ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 31 85 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? 72 07 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Tofsee_MML_2147752798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.MML!MTB"
        threat_id = "2147752798"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 86 38 bf 82 00 30 04 2f 83 6c 24 ?? 01 8b 7c 24 ?? 85 ff 0f 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Tofsee_RS_2147753475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.RS!MTB"
        threat_id = "2147753475"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 1b fe ff ff 30 04 3e b8 01 00 00 00 29 44 24 ?? 8b 74 24 ?? 85 f6 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Tofsee_KMG_2147773170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.KMG!MTB"
        threat_id = "2147773170"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fb 85 02 00 00 75 ?? ff b5 ?? ?? ?? ?? 57 57 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 30 04 31 81 fb 4a 02 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {81 fb 85 02 00 00 75 ?? ff b5 ?? ?? ?? ?? 57 57 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 30 04 31 83 fb 19 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win32_Tofsee_MAK_2147810900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.MAK!MTB"
        threat_id = "2147810900"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 06 32 55 [0-1] 88 10 8a d1 02 55 [0-1] f6 d9 00 55 [0-1] 40 4f 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 08 0f b6 14 11 33 c2 8b d0 83 e2 0f c1 e8 04 33 04 95 [0-4] 8b d0 83 e2 0f c1 e8 04 33 04 95 00 41 3b 4d 0c 72}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 01 8b d8 c0 e0 [0-1] c1 eb [0-1] 0a c3 32 c2 88 01 41 8a d0 3b ce 72}  //weight: 1, accuracy: Low
        $x_1_4 = {0f be 04 37 6b db [0-1] 2b 44 24 14 6a 00 83 e8 47 99 5d f7 fd 03 da 47 3b f9 7c}  //weight: 1, accuracy: Low
        $x_1_5 = {30 08 0f b6 10 8b ca c1 e9 [0-1] c0 e2 [0-1] 0a ca 88 08 80 f1 [0-1] 40 3b c6 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win32_Tofsee_BK_2147827126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.BK!MTB"
        threat_id = "2147827126"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {89 45 0c 8b 45 e4 01 45 0c 8b 45 0c 33 45 f8 33 c8 89 4d ec 8b 45 ec 29 45 08 81 45 f4 [0-4] ff 4d f0 8b 45 08 0f 85}  //weight: 3, accuracy: Low
        $x_1_2 = {03 c8 8b d0 c1 ea 05 03 55 e0 c1 e0 04 03 45 e8 89 4d f8 33 d0 33 d1 89 55 0c}  //weight: 1, accuracy: High
        $x_1_3 = {81 ff 6e 27 87 01 7f 0d 47 81 ff f6 ea 2b 33 0f 8c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Tofsee_KAA_2147900934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.KAA!MTB"
        threat_id = "2147900934"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "deyuhiboxowi" ascii //weight: 1
        $x_1_2 = "wocitaxahutexodezura" ascii //weight: 1
        $x_1_3 = "tudizukedi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Tofsee_AMAF_2147901103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.AMAF!MTB"
        threat_id = "2147901103"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 ec 31 45 fc 33 55 fc 89 55 d4 8b 45 d4 83 45 f8 64 29 45 f8 83 6d f8 64 8b 55 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Tofsee_KAD_2147924323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.KAD!MTB"
        threat_id = "2147924323"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {14 83 f8 01 75 01 cc 83 7d ac 00 75 40 e8 5e 9e fe ff c7 00 16 00 00 00 6a 00 68 eb}  //weight: 3, accuracy: High
        $x_4_2 = {01 cc 83 7d b0 00 75 40 e8 d3 9e fe ff c7 00 16 00 00 00 6a 00 68 ea 01 00 00 68 30 42 41}  //weight: 4, accuracy: High
        $x_5_3 = {7d fc 00 74 21 8b 55 18 f7 da 1a d2 80 e2 e0 80 c2 70 8b 45 fc 88 10 8b 4d fc 83 c1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Tofsee_GNQ_2147938459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.GNQ!MTB"
        threat_id = "2147938459"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {d3 ea 89 55 ?? 8b 45 ?? 03 45 ?? 89 45 ?? 8b 4d ?? 33 4d ?? 89 4d ?? 81 3d ?? ?? ?? ?? c1 10 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Tofsee_GNR_2147938460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tofsee.GNR!MTB"
        threat_id = "2147938460"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 ff 30 e8 e4 6e 00 00 83 ec ?? c6 04 24 ?? 8d 1d ?? ?? ?? ?? 81 eb ?? ?? ?? ?? 53 8d 15 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 52}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

