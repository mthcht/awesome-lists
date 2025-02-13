rule TrojanDownloader_Win32_Harnig_2147800273_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Harnig"
        threat_id = "2147800273"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Harnig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 73 3f 63 3d 25 64 00 25 73 25 73}  //weight: 1, accuracy: High
        $x_1_2 = {0f 85 c5 00 00 00 8b 35 a8 10 14 13 bf 00 04}  //weight: 1, accuracy: High
        $x_2_3 = {25 73 25 73 26 69 64 3d 25 64 26 63 3d 25 64 00 25 75 00 00 25 73 25 73 25 73 00 00 25 73 3f 63}  //weight: 2, accuracy: High
        $x_2_4 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00 49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Harnig_O_2147803104_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Harnig.O"
        threat_id = "2147803104"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Harnig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 10
        $x_10_2 = {52 00 45 00 47 00 20 00 61 00 64 00 64 00 20 00 48 00 4b 00 [0-4] 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 50 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 20 00 2f 00 76 00}  //weight: 10, accuracy: Low
        $x_10_3 = {6e 00 65 00 74 00 73 00 68 00 2e 00 65 00 78 00 65 00 [0-4] 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 73 00 65 00 74 00 20 00 6f 00 70 00 6d 00 6f 00 64 00 65 00 20 00 64 00 69 00 73 00 61 00 62 00 6c 00 65 00}  //weight: 10, accuracy: Low
        $x_1_4 = "127.0.0.1 www.virustotal.com" wide //weight: 1
        $x_1_5 = "127.0.0.1 www.bitdefender.com" wide //weight: 1
        $x_1_6 = "127.0.0.1 www.virusscan.jotti.org" wide //weight: 1
        $x_1_7 = "127.0.0.1 www.scanner.novirusthanks.org" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Harnig_S_2147803165_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Harnig.S"
        threat_id = "2147803165"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Harnig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".php?adv=" ascii //weight: 1
        $x_1_2 = "&code1=%s&code2=%s&id=%d&p=%s" ascii //weight: 1
        $x_2_3 = {ff d6 8a 45 ?? 04 1d 88 45 ?? 8a 45 ?? 83 c4 0c 3a c3 75 06 c6 45 ?? 30 eb 05 04 13 88 45 ?? 0f b7 45 ?? 50 8d 45 ?? 68 ?? ?? ?? ?? 50 ff d6 8a 45 ?? 04 17}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Harnig_C_2147803330_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Harnig.C"
        threat_id = "2147803330"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Harnig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 66 8b 1a 66 83 c3 b2 66 89 1a 68 ba 1f 06 00 81 e8 ?? ?? ?? 00 71 01 46 5e 66 83 02 28 66 83 02 28 83 c2 01 42 53 c7 ?? ?? ?? ?? ?? 00 5e 39 f2 75 cd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Harnig_P_2147803630_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Harnig.gen!P"
        threat_id = "2147803630"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Harnig"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 51 50 8b 45 fc 8b 08 8d 95 24 fd ff ff 52 8d 95 90 fe ff ff 52 50 ff 51 2c ?? ?? ?? ?? ?? ?? ?? ?? 81 bd cc fe ff ff 00 00 00 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0f 01 4d f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Harnig_G_2147803768_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Harnig.gen!G"
        threat_id = "2147803768"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Harnig"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {74 30 48 74 1a 48 0f 85 b0 00 00 00 68 26 80 ac c8 6a 01 e8 dc ff ff ff 68 18 40 40 00 eb 24}  //weight: 7, accuracy: High
        $x_7_2 = {68 26 80 ac c8 6a 01 e8 c3 ff ff ff 68 24 40 40 00 eb 37 68 26 80 ac c8 6a 01 e8 b0 ff ff ff 68 18 40 40 00 eb 24 68 26 80 ac c8}  //weight: 7, accuracy: High
        $x_9_3 = {64 a1 30 00 00 00 8b 40 0c 8b 70 1c ad 8b 40 08 8b c8 89 45 08 8b 41 3c 8b 74 08 78 8b 45 0c c1 e8 10 03 f1 66 85 c0 75 09 0f b7 45 0c 2b 46 10 eb 4f 83 65 fc 00}  //weight: 9, accuracy: High
        $x_7_4 = {8b 5e 24 57 8b 7e 20 03 f9 03 f9 83 7e 18 00 76 20 8b 45 08 03 07 50 e8 3e 00 00 00 3b 45 0c 74 21 ff 45 fc 8b 45 fc 83 c7 04 43 43 3b 46 18 72 e0}  //weight: 7, accuracy: High
        $x_7_5 = {8b 4d fc 3b 4e 18 5f 5b 75 09 33 c0 eb 13 0f b7 03 eb ed 8b 4d 08 8b 56 1c 8d 04 82 8b 04 08 03 c1}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_7_*))) or
            ((1 of ($x_9_*) and 2 of ($x_7_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Harnig_D_2147803782_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Harnig.gen!D"
        threat_id = "2147803782"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Harnig"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "adv6" ascii //weight: 1
        $x_1_2 = "adv7" ascii //weight: 1
        $x_1_3 = "\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_4 = "dluniq" ascii //weight: 1
        $x_1_5 = "paydial.txt" ascii //weight: 1
        $x_1_6 = "\\paydial.exe" ascii //weight: 1
        $x_1_7 = "paytime.txt" ascii //weight: 1
        $x_1_8 = "\\paytime.exe" ascii //weight: 1
        $x_1_9 = "\\countrydial.exe" ascii //weight: 1
        $x_1_10 = "tibs.php" ascii //weight: 1
        $x_1_11 = "\\tibs.exe" ascii //weight: 1
        $x_1_12 = "\\dimak" ascii //weight: 1
        $x_1_13 = "\\uniq\\kl.exe\\" ascii //weight: 1
        $x_5_14 = {61 64 76 3d 61 64 76 ?? ?? ?? 26 63 6f 64 65 31 3d 48 4e 4e 45 26 63 6f 64 65 32 3d 35 31 32 31}  //weight: 5, accuracy: Low
        $x_5_15 = "http://195.95.218.173/dl/dl.php?" ascii //weight: 5
        $x_5_16 = "http://195.95.218.173/troys/" ascii //weight: 5
        $x_1_17 = "newdial1.txt  " ascii //weight: 1
        $x_1_18 = "\\newdial1.exe  " ascii //weight: 1
        $x_1_19 = "newdial.txt " ascii //weight: 1
        $x_2_20 = "dl/dluniq.php?" ascii //weight: 2
        $x_1_21 = "\\secure32.html" ascii //weight: 1
        $x_1_22 = "toolbar.txt" ascii //weight: 1
        $x_1_23 = "\\toolbar.exe" ascii //weight: 1
        $x_1_24 = "degbes.txt" ascii //weight: 1
        $x_1_25 = "\\degbes.exe" ascii //weight: 1
        $x_1_26 = "kl.txt" ascii //weight: 1
        $x_1_27 = "\\kl.exe" ascii //weight: 1
        $x_25_28 = {53 55 ff 15 ?? ?? ?? 00 bf ?? ?? ?? 00 83 c9 ff 33 c0 f2 ae f7 d1 2b f9 50 8b f7 8b d1 8b fd 83 c9 ff f2 ae 8b ca 4f c1 e9 02 f3 a5 8b ca 55 83 e1 03 f3 a4}  //weight: 25, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((19 of ($x_1_*))) or
            ((1 of ($x_2_*) and 17 of ($x_1_*))) or
            ((1 of ($x_5_*) and 14 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_5_*) and 9 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_5_*) and 4 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_25_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Harnig_E_2147803783_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Harnig.gen!E"
        threat_id = "2147803783"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Harnig"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "adv6" ascii //weight: 1
        $x_1_2 = "adv7" ascii //weight: 1
        $x_1_3 = "\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_4 = "dluniq" ascii //weight: 1
        $x_1_5 = "paydial.txt" ascii //weight: 1
        $x_1_6 = "\\paydial.exe" ascii //weight: 1
        $x_1_7 = "paytime.txt" ascii //weight: 1
        $x_1_8 = "\\paytime.exe" ascii //weight: 1
        $x_1_9 = "\\countrydial.exe" ascii //weight: 1
        $x_1_10 = "tibs.php" ascii //weight: 1
        $x_1_11 = "\\tibs.exe" ascii //weight: 1
        $x_1_12 = "\\dimak" ascii //weight: 1
        $x_1_13 = "\\uniq\\kl.exe\\" ascii //weight: 1
        $x_5_14 = {61 64 76 3d 61 64 76 ?? ?? ?? 26 63 6f 64 65 31 3d 48 4e 4e 45 26 63 6f 64 65 32 3d 35 31 32 31}  //weight: 5, accuracy: Low
        $x_5_15 = "http://195.95.218.173/dl/dl.php?" ascii //weight: 5
        $x_5_16 = "http://195.95.218.173/troys/" ascii //weight: 5
        $x_1_17 = "newdial1.txt  " ascii //weight: 1
        $x_1_18 = "\\newdial1.exe  " ascii //weight: 1
        $x_1_19 = "newdial.txt " ascii //weight: 1
        $x_2_20 = "dl/dluniq.php?" ascii //weight: 2
        $x_1_21 = "\\secure32.html" ascii //weight: 1
        $x_1_22 = "toolbar.txt" ascii //weight: 1
        $x_1_23 = "\\toolbar.exe" ascii //weight: 1
        $x_1_24 = "degbes.txt" ascii //weight: 1
        $x_1_25 = "\\degbes.exe" ascii //weight: 1
        $x_1_26 = "kl.txt" ascii //weight: 1
        $x_1_27 = "\\kl.exe" ascii //weight: 1
        $x_25_28 = {53 55 ff 15 ?? ?? ?? 00 bf ?? ?? ?? 00 83 c9 ff 33 c0 6a ?? f2 ae f7 d1 2b f9 8b f7 8b d1 8b fd 83 c9 ff f2 ae 8b ca 4f c1 e9 02 f3 a5 8b ca 8d 44 24 ?? 83 e1 03 50 f3 a4 be ?? ?? ?? 00 56 68 ?? ?? ?? 00 68 01 00 00 80 e8 ?? ?? ?? ff}  //weight: 25, accuracy: Low
        $x_5_29 = {83 c9 ff 33 c0 6a 05 f2 ae f7 d1 2b f9 8b f7 8b d1 8b fd 83 c9 ff f2 ae 8b ca 4f c1 e9 02 f3 a5 8b ca 8d}  //weight: 5, accuracy: High
        $x_5_30 = {8a 17 8a ca 3a 10 75 1c 84 c9 74 12 8a 57 01 8a ca 3a 50 01 75 0e 47 47 40 40 84 c9 75 e2 33 ff 33 c0 eb 07 1b 0c 83 d8 ff 33 ff 3b c7}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((19 of ($x_1_*))) or
            ((1 of ($x_2_*) and 17 of ($x_1_*))) or
            ((1 of ($x_5_*) and 14 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_5_*) and 9 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_5_*) and 4 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_5_*))) or
            ((1 of ($x_25_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Harnig_F_2147803784_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Harnig.gen!F"
        threat_id = "2147803784"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Harnig"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\tsasxc.exe" ascii //weight: 1
        $x_1_2 = "\\iybkege.exe" ascii //weight: 1
        $x_1_3 = "\\xjkjtea.exe" ascii //weight: 1
        $x_1_4 = "\\dmfxyqt.exe" ascii //weight: 1
        $x_1_5 = "\\ocqhb.exe" ascii //weight: 1
        $x_1_6 = "\\ewfqb.exe" ascii //weight: 1
        $x_1_7 = "\\avirx.exe" ascii //weight: 1
        $x_1_8 = "\\odmcsk.exe" ascii //weight: 1
        $x_5_9 = {00 56 57 8b 7c 24 ?? 57 33 f6 ff d3 85 c0 7e 0c 80 04 3e d1 57 46 ff d3 3b f0 7c f4 5f 5e 5b c2 04 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Harnig_I_2147803790_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Harnig.gen!I"
        threat_id = "2147803790"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Harnig"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "F-Secure Gatekeeper Handler Starter" ascii //weight: 1
        $x_1_2 = "BackWeb Plug-in - 4476822" ascii //weight: 1
        $x_1_3 = "SharedAccess" ascii //weight: 1
        $x_1_4 = "PcCtlCom.exe" ascii //weight: 1
        $x_1_5 = "McShield.exe" ascii //weight: 1
        $x_1_6 = "McDetect.exe" ascii //weight: 1
        $x_1_7 = "McTskshd.exe" ascii //weight: 1
        $x_1_8 = "McVSEscn.exe" ascii //weight: 1
        $x_1_9 = "mcvsshld.exe" ascii //weight: 1
        $x_1_10 = "Mcdetect.exe" ascii //weight: 1
        $x_1_11 = "FSAV32.exe" ascii //weight: 1
        $x_1_12 = "Vsserv.exe" ascii //weight: 1
        $x_1_13 = "FSMA32.EXE" ascii //weight: 1
        $x_1_14 = "FSMB32.EXE" ascii //weight: 1
        $x_1_15 = "FSRW.exe" ascii //weight: 1
        $x_1_16 = "FSAW.exe" ascii //weight: 1
        $x_1_17 = "McShield" ascii //weight: 1
        $x_1_18 = "PcCtlCom" ascii //weight: 1
        $x_1_19 = "navapsvc" ascii //weight: 1
        $x_1_20 = "pccguiide.php" ascii //weight: 1
        $x_1_21 = "mcagent.exe" ascii //weight: 1
        $x_1_22 = "WinExec" ascii //weight: 1
        $x_1_23 = "TmPfw.exe" ascii //weight: 1
        $x_4_24 = {68 74 74 70 3a 2f 2f [0-16] 2e 62 69 7a 2f 70 72 6f 67 73 5f 74 72 61 66 66 2f [0-16] 2f [0-16] 2e 70 68 70 3f 65 78 70 3d}  //weight: 4, accuracy: Low
        $x_2_25 = {68 74 74 70 3a 2f 2f [0-16] 2e 62 69 7a 2f 70 72 6f 67 73 5f 74 72 61 66 66 2f [0-16] 2f}  //weight: 2, accuracy: Low
        $x_4_26 = {68 74 74 70 3a 2f 2f [0-16] 2e 62 69 7a 2f 70 72 6f 67 73 5f 65 78 65 2f [0-16] 2f [0-16] 2e 70 68 70 3f 61 64 76 3d}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((21 of ($x_1_*))) or
            ((1 of ($x_2_*) and 19 of ($x_1_*))) or
            ((1 of ($x_4_*) and 17 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_4_*) and 13 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 11 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Harnig_AB_2147803872_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Harnig.AB"
        threat_id = "2147803872"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Harnig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "wininet.dll" wide //weight: 1
        $x_1_2 = "@psapi.dll" wide //weight: 1
        $x_1_3 = "explorer.exe" ascii //weight: 1
        $x_1_4 = {68 74 74 70 3a 2f 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e [0-3] 2f 70 72 6f 67 73 2f [0-10] 2f [0-8] 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 08 59 6a 0c be ?? ?? ?? ?? 33 c0 56 8d 7d c8 68 ?? ?? ?? ?? f3 ab e8 ?? ?? ?? ff 83 c4 0c 56 8d 45 c8 50 ff 15 ?? ?? 40 00 8d 45 c8 50 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Harnig_EE_2147803965_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Harnig.EE"
        threat_id = "2147803965"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Harnig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "111"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/progs/" ascii //weight: 1
        $x_1_2 = {53 33 db 56 57 89 5d ?? c6 45 ?? 68 c6 45 ?? 74 c6 45 ?? 74 c6 45 ?? 70 c6 45 ?? 3a c6 45 ?? 2f c6 45 ?? 2f}  //weight: 1, accuracy: Low
        $x_10_3 = {83 f8 ff 89 45 fc 0f 84 e7 00 00 00 8d 85 d4 fe ff ff c7 85 ?? ?? ?? ?? ?? 01 00 00 50 ff 75 fc e8 ?? ?? ?? ?? 85 c0 0f 84 bd 00 00 00 53 56 8b 35 ?? ?? ?? ?? 57 bf 00 01 00 00 ff 75 08 8d 85 f8 fe ff ff 50}  //weight: 10, accuracy: Low
        $x_10_4 = {04 01 00 00 ?? ff ?? bf ?? ?? ?? ?? 83 c9 ff 33 c0 [0-5] f2 ae f7 d1 2b f9}  //weight: 10, accuracy: Low
        $x_50_5 = {8b f7 8b d1 8b ?? 83 c9 ff f2 ae 8b ca 4f c1 e9 02 f3 a5 8b ca}  //weight: 50, accuracy: Low
        $x_50_6 = {55 8b ec 83 ec 44 56 ff 15 ?? ?? ?? ?? 8b f0 8a 06 3c 22 75 14 3c 22 74 08 8a 46 01 46 84 c0 75 f4 80 3e 22 75 0d 46 eb 0a 3c 20 7e 06 46 80 3e 20 7f fa 8a 06 84 c0 74 04 3c 20 7e e9 83 65 e8 00 8d 45 bc 50}  //weight: 50, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_50_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_50_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Harnig_K_2147803980_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Harnig.gen!K"
        threat_id = "2147803980"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Harnig"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7c 24 10 33 c0 8a 07 47 50 e8 ?? ff ff ff 88 04 1e 46 3b 74 24 18 7c eb 80 24 1e 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 26 80 ac c8 6a 01 e8 ?? ?? ff ff [0-3] (56|68 ?? ?? ?? ??) ff d0}  //weight: 1, accuracy: Low
        $x_1_3 = {68 d6 4b 7f 7f 6a 01 e8 ?? ?? ff ff [0-3] (56|68 ?? ?? ?? ??) ff d0}  //weight: 1, accuracy: Low
        $x_1_4 = {68 26 80 ac c8 ?? e8 ?? ff ff ff 83 c4 14 56 ff d0 eb ?? 6a 0c be}  //weight: 1, accuracy: Low
        $x_1_5 = {0f 01 4d f9 8b 45 fb 25 00 00 f0 ff 3d 00 00 c0 ff 75 04 c6 45 ff 01 0f b6 45 ff c9 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Harnig_N_2147804121_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Harnig.gen!N"
        threat_id = "2147804121"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Harnig"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f 01 4d f9 8b 45 fb 25 00 00 f0 ff 3d 00 00 c0 ff 75 04 c6 45 ff 01 0f b6 45 ff c9 c3}  //weight: 3, accuracy: High
        $x_1_2 = {89 45 f0 ff 15 ?? ?? ?? ?? ff 75 f0 89 45 f4 ff 15 ?? ?? ?? ?? 83 7d f4 02 74 0d ff 45 fc 83 7d fc 02 0f 8c}  //weight: 1, accuracy: Low
        $x_1_3 = {83 ff 01 75 07 68 ?? ?? ?? ?? eb ?? 83 ff 02 75 07 68 ?? ?? ?? ?? eb ?? 83 ff 03 75 0e}  //weight: 1, accuracy: Low
        $x_1_4 = "uniq.php" ascii //weight: 1
        $x_1_5 = "%u.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Harnig_P_2147804207_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Harnig.P"
        threat_id = "2147804207"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Harnig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 01 4d f9 8b 45 fb 25 00 00 f0 ff 3d 00 00 c0 ff 75 04 c6 45 ff 01 0f b6 45 ff}  //weight: 1, accuracy: High
        $x_1_2 = {51 50 ff 15 ?? ?? ?? ?? 6a 04 89 45 08 8d 45 e0 50 6a 02 ff 75 f4 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 11 b8 20 20 20 20 0b d0 81 fa 65 78 70 6c 75 77 8b 51 04 0b d0 81 fa 6f 72 65 72 75 6a 8b 49 08 0b c8 81 f9 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_4 = {2e 70 68 70 3f 61 64 76 3d 61 64 76 [0-5] 26 63 6f 64 65 31 3d 25 73 26 63 6f 64 65 32 3d 25 73 26 69 64 3d 25 64 26 70 3d 25 73 00}  //weight: 1, accuracy: Low
        $x_1_5 = "http://ccfairy.com/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

