rule Trojan_Win32_TrickBot_O_2147727926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.O!bit"
        threat_id = "2147727926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 8b c2 66 8b 10 42 42 81 fa 4f 5a 00 00 74 11 2d 00 00 01 00 66 8b 10 42 81 fa 4e 5a 00 00 75 ef 8b f8 e9 06 2f fd ff}  //weight: 1, accuracy: High
        $x_1_2 = {8b 54 24 18 8b 74 24 14 8b 4c 24 10 8b 7c 24 0c 85 d2 74 0e 52 ac 30 07 5a 47 4a e2 f3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_G_2147730060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.G"
        threat_id = "2147730060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 8b 45 04 05 ?? ?? ?? ?? 8b f0 6a ?? 5b 53 51 8b c6 8b 00 46 8b 0f 33 c1 59 88 07 47 4b 75 06 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_I_2147730101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.I"
        threat_id = "2147730101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 0c 83 c0 0c c6 80 ?? ?? ?? ?? 00 8b 45 0c [0-3] 89 45 ?? eb ?? 8b 45 ?? 83 c0 0c c6 80 ?? ?? ?? ?? 01 [0-4] 83 7d ?? ?? [0-7] c7 45 ?? 00 00 00 00 c7 45 ?? 4c 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_I_2147730101_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.I"
        threat_id = "2147730101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 2b 83 c3 04 33 2f 83 c7 04 89 29 83 c1 04 3b de 0f 43 da 81 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 04 00 00 00 50 50 50 50 50 50 50 50 6a 02 68 40 10 00 00 e8}  //weight: 1, accuracy: High
        $x_1_3 = {8a e2 c0 e0 02 c0 e2 04 c0 ec 04 80 e4 03 0a e0 8a 44 ?? ?? 88 64 ?? ?? 8a f0 c0 e0 06 02 44 ?? ?? c0 ee 02 80 e6 0f 0a f2 88 74 ?? ?? 88 44 ?? ?? 88 26}  //weight: 1, accuracy: Low
        $x_1_4 = {a3 3c 9a 87 01 b9 90 5f 01 00 68 c0 27 09 00 68 20 bf 02 00 51 51 50 ff 15 d8 b2 87 01 68 00 08 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {8d 4c 24 1c ba 20 00 00 00 c7 41 f4 08 02 00 00 c7 41 f8 10 66 00 00 89 51 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_TrickBot_P_2147730592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.P"
        threat_id = "2147730592"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7c 24 0c [0-1] ?? ?? ?? ?? ?? ?? ?? ?? 8b 54 24 18 85 d2 74 ?? ac 52 30 07 5a 4a 47 e2 f3 5e 5b 33 c0 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 58 10 48 89 70 18 49 8b d9 49 8b f8 48 8b f2 b9 30 00 00 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_Q_2147730594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.Q"
        threat_id = "2147730594"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "k|}p!T2Zrrj1kKc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_SA_2147733501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.SA!MTB"
        threat_id = "2147733501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 5c 8c 10 8b 74 bc 10 89 74 8c 10 0f b6 f3 89 74 bc 10 8b 5c 8c 10 03 de 81 e3 ff 00 00 80 79 ?? 4b 81 cb 00 ff ff ff 43 0f b6 5c 9c 10 30 1c 2a 42 3b d0 72}  //weight: 1, accuracy: Low
        $x_1_2 = "u9-c*JnT+iXBxsP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_SB_2147733505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.SB!MTB"
        threat_id = "2147733505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 50 6a 40 6a 05 56 ff ?? ?? ?? ?? 00 8b ?? ?? ?? ?? 00 8d 4c 24 0c 6a 01 51 56 c7 44 24 18 e9 00 00 00 ff d7 8d 44 24 08 6a 04 8b 54 24 1c 50 2b d6 70 ?? 83 ea 05 70 ?? 83 c6 01 89 54 24 10 70 ?? 56 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_U_2147733538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.U"
        threat_id = "2147733538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c2 b0 00 8b 4d e0 89 d7 f2 ae 89 c8 f7 d0 8d 48 ff 8b 45 f0 ba 00 00 00 00 f7 f1 89 d0 03 45 08 8a 00 31 f0 88 03 ff 45 f0 8b 45 f0 3b 45 10 0f 95 c0 84 c0 75 aa}  //weight: 1, accuracy: High
        $x_1_2 = {c1 e8 0d 8b 4d fc c1 e1 13 0b c1 89 45 fc 8b 45 08 0f be 00 83 f8 61 7c 0e 8b 45 08 0f be}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_SC_2147734155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.SC!bit"
        threat_id = "2147734155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 83 39 01 75 ?? 8b 51 14 8b 41 10 8b fb 2b fa 3b f8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 74 24 18 8b 45 00 8b fe 85 c0 74 ?? 66 83 38 01 75 ?? 8b 50 14 8b 48 10 8b f3 2b f2 3b f1 72}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4d 00 8b 51 0c 66 0f b6 34 02 66 2b f7 70 ?? 66 85 f6 7d ?? 66 81 c6 00 01 70 ?? 85 c9 74 ?? 66 83 39 01 75 16 8b 51 14 8b 41 10 8b fb 2b fa 3b f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_R_2147735041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.R!MTB"
        threat_id = "2147735041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 db 4b 68 2f f7 e1 8b c1 2b c2 d1 e8 03 c2 c1 e8 04 6b c0 1b 8b d1 2b d0 8a 04 1a 30 04 31 83 c1 01 3b cf 75}  //weight: 1, accuracy: High
        $x_2_2 = {83 ee 08 8b da 8b ce d3 fb 83 c7 01 85 f6 88 5c 07 ff 75 ec 8b 4c 24 18 83 c5 04 83 e9 01 89 4c 24 18 0f 85}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_R_2147735041_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.R!MTB"
        threat_id = "2147735041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 47 71 4a 46 6b 59 65 4a 40 6f 4e 6b 71 37 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 4b 4e 44 51 5a 4b 50 67 62 53 51 53 77 50 00}  //weight: 1, accuracy: High
        $x_1_3 = "5w5EzPC0C10QrKw(" ascii //weight: 1
        $x_1_4 = {8b 45 f8 8d 50 01 89 d0 c1 f8 1f c1 e8 18 01 c2 0f b6 d2 29 c2 89 d0 89 45 f8 8b 45 f8 8b 94 85 ec fb ff ff 8b 45 f4 01 c2 89 d0 c1 f8 1f c1 e8 18 01 c2 0f b6 d2 29 c2 89 d0 89 45 f4 8b 45 f8 8b 84 85 ec fb ff ff 88 45 ef 8b 45 f4 8b 94 85 ec fb ff ff 8b 45 f8 89 94 85 ec fb ff ff 0f b6 55 ef 8b 45 f4 89 94 85 ec fb ff ff 8b 45 f0 8b 55 08 8d 0c 02 8b 45 f0 8b 55 08 01 d0 0f b6 00 89 c3 8b 45 f8 8b 94 85 ec fb ff ff 8b 45 f4 8b 84 85 ec fb ff ff 01 c2 89 d0 c1 f8 1f c1 e8 18 01 c2 0f b6 d2 29 c2 89 d0 8b 84 85 ec fb ff ff 31 d8 88 01 83 45 f0 01 8b 45 f0 3b 45 10 0f 82 3c ff ff ff}  //weight: 1, accuracy: High
        $x_1_5 = {8b 45 f4 8d 50 01 89 d0 c1 f8 1f c1 e8 18 01 c2 81 e2 ff 00 00 00 89 d6 29 c6 89 f0 89 45 f4 8b 45 f4 8b 94 85 e8 fb ff ff 8b 45 f0 01 c2 89 d0 c1 f8 1f c1 e8 18 01 c2 81 e2 ff 00 00 00 89 d1 29 c1 89 c8 89 45 f0 8b 45 f4 8b 84 85 e8 fb ff ff 88 45 eb 8b 45 f0 8b 94 85 e8 fb ff ff 8b 45 f4 89 94 85 e8 fb ff ff 0f b6 55 eb 8b 45 f0 89 94 85 e8 fb ff ff 8b 45 ec 8b 55 08 8d 0c 02 8b 45 ec 8b 55 08 01 d0 0f b6 00 89 c3 8b 45 f4 8b 94 85 e8 fb ff ff 8b 45 f0 8b 84 85 e8 fb ff ff 01 c2 89 d0 c1 f8 1f c1 e8 18 01 c2 81 e2 ff 00 00 00 89 d6 29 c6 89 f0 8b 84 85 e8 fb ff ff 31 d8 88 01 83 45 ec 01 8b 45 ec 3b 45 10 0f 92 c0 84 c0 0f 85 28 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_TrickBot_R_2147735041_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.R!MTB"
        threat_id = "2147735041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 09 8b 45 ?? 83 c0 01 89 45 ?? 8b 4d ?? 3b 4d 10 74 4e 8b 55 08 89 55 ?? 8b 45 ?? 83 c0 01 89 45 ?? 8b 4d ?? 8a 11 88 55 ?? 83 45 ?? 01 80 7d ?? 00 75 ee 8b 45 ?? 2b 45 ?? 89 45 ec 8b 45 ?? 33 d2 f7 75 ec 8b 4d 08 0f be 14 11 8b 45 0c 03 45 ?? 0f b6 08 33 ca 8b 55 0c 03 55 ?? 88 0a eb a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_SD_2147735306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.SD!bit"
        threat_id = "2147735306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 20 c7 45 f4 00 00 00 00 8b 45 f4 3b 45 10 74 3f 8b 55 0c 8b 45 f4 8d 1c 02 8b 55 0c 8b 45 f4 01 d0 0f b6 00 89 c6 8b 45 08 89 04 24 e8 ?? ?? ?? ?? 89 c1 8b 45 f4 ba 00 00 00 00 f7 f1 8b 45 08 01 d0 0f b6 00 31 f0 88 03 83 45 f4 01 eb b9 [0-16] 83 c4 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_SE_2147735456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.SE!bit"
        threat_id = "2147735456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8d 14 85 00 00 00 00 8b 45 08 01 d0 8b 00 8b 55 ?? 8d 0c 95 00 00 00 00 8b 55 08 01 ca 33 45 10 89 02 83 45 ?? 01 8b 45}  //weight: 3, accuracy: Low
        $x_3_2 = {89 d0 c1 e0 02 01 d0 c1 e0 03 89 c2 8b 45 ?? 01 d0}  //weight: 3, accuracy: Low
        $x_3_3 = {89 c3 be 00 00 00 00 01 d3 11 ce 89 d8 89 f2 c7 44 24 ?? 00 00 00 00 8b b5 ?? ?? ?? ?? 89 74 24 ?? 89 7c 24 ?? 89 44 24 ?? 8b 45 08 89 04 24 a1 ?? ?? ?? ?? ff d0}  //weight: 3, accuracy: Low
        $x_2_4 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" wide //weight: 2
        $x_2_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 2
        $x_2_6 = "WARNING - RUN ON VM" wide //weight: 2
        $x_1_7 = "SELECT * FROM Win32_ComputerSystem" wide //weight: 1
        $x_1_8 = "SELECT * FROM Win32_BIOS" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_TrickBot_X_2147735891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.X"
        threat_id = "2147735891"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Content-Disposition: form-data; name=\"proclist\"" ascii //weight: 2
        $x_2_2 = "Content-Disposition: form-data; name=\"sysinfo\"" ascii //weight: 2
        $x_1_3 = "***PROCESS LIST***" ascii //weight: 1
        $x_4_4 = "Dpost servers unavailable" ascii //weight: 4
        $x_4_5 = "sent PASSWORDS to DPost server" ascii //weight: 4
        $x_1_6 = "Software\\Google\\Chrome\\BLBeacon" ascii //weight: 1
        $x_1_7 = "sbox_alternate_desktop" wide //weight: 1
        $x_3_8 = "webinject32.pdb" ascii //weight: 3
        $x_2_9 = "conf ctl=\"SetConf\" file=\"dpost\" period=\"" ascii //weight: 2
        $x_2_10 = "conf ctl=\"dpost\" file=\"dpost\" period=\"" ascii //weight: 2
        $x_2_11 = "ESTR_PASS_" ascii //weight: 2
        $x_1_12 = "\\User Data\\Default\\Login Data.bak" ascii //weight: 1
        $x_1_13 = "Grab_Passwords_Chrome() success" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_TrickBot_SZ_2147739865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.SZ!MTB"
        threat_id = "2147739865"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e4 8b 55 0c 8d 1c 02 8b 45 e4 8b 55 0c 01 d0 0f b6 00 89 c6 8b 45 08 89 04 24 e8 ?? ?? ?? ?? 89 c7 8b 45 e4 ba 00 00 00 00 f7 f7 89 d1 89 ca 8b 45 08 01 d0 0f b6 00 31 f0 88 03 83 45 e4 01 8b 45 e4 3b 45 10 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_DA_2147739947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DA!MTB"
        threat_id = "2147739947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d0 0a 44 24 ?? f6 d2 f6 d1 0a d1 22 d0 8b 44 24 ?? 88 10 [0-4] 83 6c 24 ?? 01 89 44 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_DA_2147739947_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DA!MTB"
        threat_id = "2147739947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 51 b9 ?? 00 00 00 33 d2 f7 f1 59 8a 04 13 30 04 0e 41 3b f9 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 04 a8 03 75 ?? 8b 10 83 c0 04 8b ca 81 ea 01 01 01 01 81 e2 80 80 80 80 74 eb f7 d1 23 d1 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_2147740186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot!MTB"
        threat_id = "2147740186"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 10 74 24 8b 45 fc 33 d2 f7 75 14 8b 45 08 0f be 0c 10 8b 55 0c 03 55 fc 0f b6 02 33 c1 8b 4d 0c 03 4d fc 88 01 eb cb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_DF_2147740887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DF!MTB"
        threat_id = "2147740887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 08 40 84 c9 75 ?? 2b c2 8b f8 33 c9 33 d2 8b c1 f7 f7 41 8a 92 ?? ?? ?? ?? 30 54 31 ff 81 f9 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_BB_2147741109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.BB!MTB"
        threat_id = "2147741109"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 50 01 8a 08 40 84 c9 75 f9 2b c2 8b f8 33 c9 8b c1 33 d2 f7 f7 41 8a 82 ?? ?? ?? ?? 30 44 31 ff 81 f9 60 11 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_BB_2147741109_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.BB!MTB"
        threat_id = "2147741109"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c5 99 bd f1 17 00 00 f7 fd 8b ea 8d 04 29 50 56 89 44 24 ?? e8 ?? ?? ?? ?? 8b 54 24 ?? 0f b6 0a 0f b6 06 03 c1 99 b9 f1 17 00 00 f7 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_GA_2147741118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.GA!MTB"
        threat_id = "2147741118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e9 c1 fa ?? 8b c2 c1 e8 ?? 03 c2 [0-10] 8a 04 1a 30 04 31 41 3b cf 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_GA_2147741118_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.GA!MTB"
        threat_id = "2147741118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 07 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 45 ?? 83 c4 ?? 8a 8c 15 ?? ?? ?? ?? 30 08 40 ff 4d ?? 89 45 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_AB_2147741194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.AB"
        threat_id = "2147741194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tabdll_x64.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_DSK_2147741339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DSK!MTB"
        threat_id = "2147741339"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b c1 33 d2 f7 f3 41 8a 04 2a 30 44 31 ff 3b cf 75}  //weight: 2, accuracy: High
        $x_1_2 = "2#JNMHXFA@2*EDC1V}JZf3OLKXMtJ|U" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_DSK_2147741339_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DSK!MTB"
        threat_id = "2147741339"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 db 4b 68 2f f7 e1 8b c1 2b c2 d1 e8 03 c2 c1 e8 04 6b c0 1b 8b d1 2b d0 8a 04 1a 30 04 31 83 c1 01 3b cf}  //weight: 2, accuracy: High
        $x_1_2 = "TyWACk8bt}eA3A12c5TTJvOmYbE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_GN_2147741459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.GN!MTB"
        threat_id = "2147741459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 83 c0 ?? 89 45 fc 8b 4d fc 3b 4d 10 74 ?? 8b 45 fc 33 d2 f7 75 14 8b 45 0c 03 45 fc 8b 4d 08 8a 00 32 04 11 8b 4d 0c 03 4d fc 88 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_GN_2147741459_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.GN!MTB"
        threat_id = "2147741459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 40 68 00 10 00 00 57 6a 00 ff d3}  //weight: 1, accuracy: High
        $x_1_2 = "\\DLLPORTABLEX86\\32\\Release\\dll32custom.pdb" ascii //weight: 1
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_1_4 = "UnsOretW" ascii //weight: 1
        $x_1_5 = "dpi1024" ascii //weight: 1
        $x_1_6 = "dpi360" ascii //weight: 1
        $x_1_7 = "dpi640" ascii //weight: 1
        $x_1_8 = "1.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_GE_2147741460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.GE!MTB"
        threat_id = "2147741460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 74 24 10 74 [0-12] 8b 44 24 10 8d 0c 06 33 d2 6a ?? 8b c6 ?? f7 ?? 8b 44 24 ?? 8a 04 02 30 01 46 3b 74 24 14 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_GE_2147741460_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.GE!MTB"
        threat_id = "2147741460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 44 24 1f 0f b6 f0 8a 44 24 1e 0f b6 f8 89 f8 09 f0 88 44 24 1e c7 44 24 40 91 00 00 00 8a 44 24 17 0f b6 f0 8a 44 24 1e 0f b6 f8 89 f8 31 f0 88 44 24 1e}  //weight: 1, accuracy: High
        $x_1_2 = "TyreDokgW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_GM_2147741743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.GM!MTB"
        threat_id = "2147741743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 f6 0f 95 c3 [0-16] 85 c0 [0-16] 8a 1a 48 30 19 42 41 4e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_GM_2147741743_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.GM!MTB"
        threat_id = "2147741743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 99 b9 ?? ?? ?? ?? f7 f9 8b 45 08 0f be 0c ?? 8b 55 0c 03 55 f8 0f b6 02 33 c1 8b 4d 0c 03 4d f8 88 01 8b 55 fc 83 c2 01 89 55 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_2147742011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot!ibt"
        threat_id = "2147742011"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "F:\\Projects\\WebInject\\bin\\x86\\Release_nologs\\payload32.pdb" ascii //weight: 3
        $x_1_2 = "microsoftedgecp.exe iexplore.exe firefox.exe chrome.exe" ascii //weight: 1
        $x_2_3 = {03 da 8b 37 03 f2 33 c9 8a 06 c1 c9 0d 0f be c0 03 c8 46 8a 06 84 c0 75 f1 81 f9 8e 4e 0e ec 74 18 81 f9 aa fc 0d 7c 74 10 81 f9 54 ca af 91 74 08 81 f9 ef ce e0 60 75 5b 0f b7 03 8b 75 e0 8d 04 82 03 46 1c 81 f9 8e 4e 0e ec 75 09 8b 00 03 c2 89 45 f0 eb 31 81 f9 aa fc 0d 7c 75 09}  //weight: 2, accuracy: High
        $x_2_4 = {8a 02 c1 c9 0d 3c 61 0f b6 c0 72 03 83 c1 e0 03 c8 81 c6 ff ff 00 00 42 66 85 f6 75 e3 81 f9 5b bc 4a 6a 0f 85 cb 00 00 00 8b 53 10 c7 45 fc 04 00 00 00 8b 42 3c 8b 44 10 78 03 c2 89 45 e0 8b 78 20 8b 58 24 03 fa}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_TrickBot_AC_2147742282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.AC"
        threat_id = "2147742282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "185.142.99.19" ascii //weight: 3
        $x_2_2 = "VNCSRV.pdb" ascii //weight: 2
        $x_1_3 = "/K schtasks.exe |more" ascii //weight: 1
        $x_1_4 = "--allow-no-sandbox-job" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_TrickBot_CG_2147742915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.CG!MTB"
        threat_id = "2147742915"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 6e 04 eb ?? 8d 6e 04 33 d2 8b ?? f7 f3 8a ?? ?? 30 ?? 47 eb 40 00 8b ?? ?? 2b ?? 3b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_AE_2147743513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.AE!MSR"
        threat_id = "2147743513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 8b 06 8b 0f 46 33 c1 88 07 47 4b 58 8b c8 75 06}  //weight: 1, accuracy: High
        $x_1_2 = {59 ff d2 89 68 02 6a ?? 8b d0 ff d2 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_RK_2147743758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.RK!MSR"
        threat_id = "2147743758"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d 0c e8 90 09 00 00 39 45 fc 74 36 8b 4d fc 51 8b 4d 0c e8 9f 09 00 00 89 45 f8 8b 45 fc 33 d2 b9 22 00 00 00 f7 f1 52 8b 4d 08 e8 97 08 00 00 0f be 10 8b 45 f8 0f be 08 33 ca 8b 55 f8 88 0a eb b4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_BM_2147743795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.BM!MTB"
        threat_id = "2147743795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 18 88 11 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 02 5d 10 8b 45 08 8b 4d fc 83 c4 0c 0f b6 d3 03 c1 8a 94 15 f0 fe ff ff 30 10 41 3b 4d 0c 89 4d fc 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 f1 8a 04 3e 8a 14 ?? 32 c2 88 04 3e 46 3b f5 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBot_PDSK_2147745109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.PDSK!MTB"
        threat_id = "2147745109"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 75 fc 09 10 a1 ?? ?? ?? ?? 8b 00 89 01 66 a1 ?? ?? ?? ?? 66 83 c0 fa 66 a3 0b 00 a1 ?? ?? ?? ?? 8b 0d}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 06 01 d8 8b 55 e4 30 10 43 8b 06 3b 58 f4 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBot_RL_2147745240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.RL!MSR"
        threat_id = "2147745240"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 10 74 ?? 8b 55 08 52 e8 ?? ?? 00 00 83 c4 04 8b c8 8b 45 fc 33 d2 f7 f1 8b 45 08 0f be 0c 10 8b 55 0c 03 55 fc 0f b6 02 33 c1 8b 4d 0c 03 4d fc 88 01 eb be}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_VDSK_2147745264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.VDSK!MTB"
        threat_id = "2147745264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 84 15 ec d1 ff ff 33 c1 8b 4d f4 88 84 0d ec d1 ff ff eb}  //weight: 2, accuracy: High
        $x_1_2 = {89 f8 b9 cd cc cc cc f7 e1 c1 ea 02 83 e2 fe 8d 2c 92 f7 dd 56 e8}  //weight: 1, accuracy: High
        $x_1_3 = {83 c4 04 8a 84 2b ?? ?? ?? ?? 30 83 ?? ?? ?? ?? 56 e8 05 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_TrickBot_PVD_2147745265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.PVD!MTB"
        threat_id = "2147745265"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 4c 38 03 8a d1 c0 e2 06 0a 54 38 02 8a c1 24 f0 80 e1 fc c0 e0 02 83 c7 04 0a 44 24 18 c0 e1 04 0a 4c 24 13}  //weight: 2, accuracy: High
        $x_2_2 = {6a 59 59 33 d2 8b c6 f7 f1 c7 04 24 ?? ?? ?? ?? 8a 82 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? e8 ?? ?? ?? ?? c7 04 24 ?? ?? ?? ?? e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBot_ARC_2147745447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.ARC!MSR"
        threat_id = "2147745447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "others as well.exe" ascii //weight: 1
        $x_1_2 = "Gs8LHszJHs" ascii //weight: 1
        $x_1_3 = "Sungai Petani Malaysia" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_CB_2147745737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.CB!MTB"
        threat_id = "2147745737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c6 51 03 de 89 44 24 2c e8 ?? ?? ?? ?? 83 c4 04 50 e8 ?? ?? ?? ?? 8a 08 83 c4 0c 33 d2 84 c9 74 ?? 8d 64 24 00 8b ea c1 e5 13 c1 ea 0d 0b d5 80 f9 61 0f b6 c9 72 ?? 83 e9 20 03 d1 8a 48 01 40 84 c9 75 ?? 81 fa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_CB_2147745737_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.CB!MTB"
        threat_id = "2147745737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 0a 84 c9 74 ?? 56 8b f0 c1 e6 13 c1 e8 0d 0b c6 80 f9 61 72 ?? 81 e1 ff 00 00 00 83 e9 20 eb ?? 81 e1 ff 00 00 00 03 c1 8a 4a 01 42 84 c9 75}  //weight: 2, accuracy: Low
        $x_1_2 = {6a 00 ff 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 03 80 00 00 c7 05 ?? ?? ?? ?? 01 68 00 00 c7 05 ?? ?? ?? ?? 01 00 00 00 c7 05 ?? ?? ?? ?? 40 00 00 00 c7 05 ?? ?? ?? ?? 00 10 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_VDS_2147746161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.VDS!MTB"
        threat_id = "2147746161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b9 27 00 00 00 f7 f1 8b 44 24 14 8a 0c 50 8a 14 1e 32 d1 88 14 1e 46 3b f5 75}  //weight: 2, accuracy: High
        $x_2_2 = {8b 54 24 14 c1 e8 05 6b c0 23 8b ce 2b c8 8a 04 4a 30 04 1e 83 c6 01 3b f5 75 c4}  //weight: 2, accuracy: High
        $x_2_3 = "sgyavajwivmlmzfumfncv" wide //weight: 2
        $x_2_4 = "nwsplnmaspckhssmxaijxldx" wide //weight: 2
        $x_2_5 = "cvdfXzsdEjgbCxdSaqKLjNtD" ascii //weight: 2
        $x_2_6 = "gbdiqhbsxtjpxqwltvgyosiqpzfk" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBot_CA_2147746188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.CA!MTB"
        threat_id = "2147746188"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 8d 49 00 8b f0 c1 e6 13 c1 e8 0d 0b c6 80 f9 61 0f b6 c9 72 03 83 e9 20 03 c1 8a 4a 01 42 84 c9 75}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 ff 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 03 80 00 00 c7 05 ?? ?? ?? ?? 01 68 00 00 c7 05 ?? ?? ?? ?? 01 00 00 00 c7 05 ?? ?? ?? ?? 40 00 00 00 c7 05 ?? ?? ?? ?? 00 10 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_PVS_2147747809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.PVS!MTB"
        threat_id = "2147747809"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 4c 24 10 8b 84 24 ?? ?? ?? ?? 02 d9 8a 14 06 81 e3 ff 00 00 00 8a 4c 1c 14 32 d1 88 14 06 8b 84 24 ?? ?? ?? ?? 46 3b f0}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 55 10 89 54 9e 08 8b 5d fc 03 da 23 d8 8a 54 9e 08 32 51 06 ff 4d f8 88 57 06}  //weight: 2, accuracy: High
        $x_2_3 = {69 c9 d6 2f 00 00 8b 5c 24 10 81 c5 e8 68 74 01 89 2d ?? ?? ?? ?? 03 ce 89 ac 1f 11 e2 ff ff 0f b7 c9 39 15 ?? ?? ?? ?? 06 00 8b 3d}  //weight: 2, accuracy: Low
        $x_2_4 = {8a 04 0b c7 44 24 28 d9 b5 31 0d 8b 5c 24 18 8a 24 3b 30 c4 8b 7c 24 1c 88 24 0f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBot_VDK_2147747840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.VDK!MTB"
        threat_id = "2147747840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "g05d7k6gWFd3hytPPowE" ascii //weight: 2
        $x_2_2 = "fsI1zoFkP48sCiog6Soz" ascii //weight: 2
        $x_2_3 = "g5G0xcJM8JHvxptVJgyyni" ascii //weight: 2
        $x_2_4 = "hFKvndtoPMgh3ONOkZQBVEW3" ascii //weight: 2
        $x_2_5 = "hQXk4vpvHdjzniKUk0Hunvu8" ascii //weight: 2
        $x_2_6 = "hn46YagaM6xIFVRj3ZerZbwl" ascii //weight: 2
        $x_2_7 = "hmPBxdWX53dTtJAnOQgTFe4Qj" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBot_GB_2147747842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.GB!MTB"
        threat_id = "2147747842"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 8a [0-3] 03 e8 89 44 [0-2] 81 e5 ff 00 00 00 8a 5c [0-2] 88 5c [0-2] 88 44 [0-2] ff 15 [0-4] 8a 4c [0-2] 8b 84 [0-5] 02 d9 8a [0-2] 81 ?? ff 00 00 00 8a [0-3] 32 ?? 88 [0-2] 8b [0-6] 46 3b [0-9] 81 c4 [0-4] c3 8d 00 47 33 [0-3] ff 00 00 00 33}  //weight: 1, accuracy: Low
        $x_1_2 = "VirtualAllocExNuma" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_GB_2147747842_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.GB!MTB"
        threat_id = "2147747842"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "c:\\developer\\webinject\\http-lib\\parser.c" ascii //weight: 10
        $x_1_2 = "data_inject" ascii //weight: 1
        $x_1_3 = "data_before" ascii //weight: 1
        $x_1_4 = "data_after" ascii //weight: 1
        $x_1_5 = "data_end" ascii //weight: 1
        $x_1_6 = "wbi-x86.dll" ascii //weight: 1
        $x_1_7 = "wbi-x64.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_TrickBot_PVK_2147747954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.PVK!MTB"
        threat_id = "2147747954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 02 8b 4d fc 03 4d f8 81 e1 ff 00 00 00 33 d2 8a 94 0d 14 fd ff ff 33 c2 8b 4d 08 03 4d ec 88 01}  //weight: 2, accuracy: High
        $x_2_2 = {8a 0c 11 8b 54 24 2c 8b 5c 24 04 32 0c 1a 66 89 44 24 3e 8b 54 24 28 88 0c 1a 83 c3 01 8b 4c 24 38}  //weight: 2, accuracy: High
        $x_2_3 = {8a 3c 11 0f b6 cb 01 f9 21 f1 8b 74 24 34 32 3c 0e 8a 5c 24 2f 88 5c 24 61 8b 4c 24 24 88 3c 11}  //weight: 2, accuracy: High
        $x_2_4 = {8b 55 fc 81 ea 00 10 00 00 89 55 fc 8b 45 08 33 45 0c 89 45 08 8b 4d fc c1 e1 03 89 4d fc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBot_CD_2147747978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.CD!MTB"
        threat_id = "2147747978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c2 8b 4d ?? 03 4d ?? 88 01 e9 1f 00 8b 55 ?? 03 55 ?? 33 c0 8a 02 8b 4d ?? 03 4d ?? 81 e1 ff 00 00 00 33 d2 8a 94 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {81 e1 ff 00 00 00 89 4d ?? 8b 55 ?? 33 c0 8a 84 15 ?? ?? ?? ?? 89 45 ?? 8b 4d ?? 8a 55 ?? 88 94 0d ?? ?? ?? ?? 8b 45 ?? 8a 4d ?? 88 8c 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_CC_2147748028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.CC!MTB"
        threat_id = "2147748028"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 da 88 1c 07 8b 84 24 ?? ?? ?? ?? 47 3b f8 0f 8c ?? ?? ?? ?? 5b 5f 5e 5d 81 c4 44 03 00 00 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 00 ff d6 6a 00 6a 00 ff d6 6a 00 6a 00 ff d6 6a 00 6a 00 ff d6 8a 4c 24 ?? 8b 84 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_CE_2147748029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.CE!MTB"
        threat_id = "2147748029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 0a 6a 05 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8a 4c 24 ?? 8b 84 24 ?? ?? ?? ?? 02 d9 83 c4 30 8a 14 06 81 e3 ff 00 00 00 8a 4c 1c ?? 32 d1 88 14 06 8b 84 24 ?? ?? ?? ?? 46 3b f0 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_VSD_2147748604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.VSD!MTB"
        threat_id = "2147748604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "dtdKKygFovrK" ascii //weight: 2
        $x_2_2 = "ezT2On77iHRC5USH" ascii //weight: 2
        $x_2_3 = "fv5NhdLRpDJEvteyPr" ascii //weight: 2
        $x_2_4 = "jk0tJS0c3Jz0cpVFiiP" ascii //weight: 2
        $x_2_5 = "f7R435exQC7qzYOeerz" ascii //weight: 2
        $x_2_6 = "gNN8z4FE8J7jMIAni0Ig" ascii //weight: 2
        $x_2_7 = "fq1npgTZUEnpjPYpofjD" ascii //weight: 2
        $x_2_8 = "gwJATZS21CbdRCiHYMUVj" ascii //weight: 2
        $x_2_9 = "gtdyWD0QcBx2gmnju1ePT" ascii //weight: 2
        $x_2_10 = "g7zs1L4NMtIKD8EacpaD0M" ascii //weight: 2
        $x_2_11 = "gATQVwFZQfFzFVdoFtRw3QP" ascii //weight: 2
        $x_2_12 = "hRbblm4nre6RSl4yTDeXTvej" ascii //weight: 2
        $x_2_13 = "hqMpmtIDOpqXreCZJEV8iRxbtk" ascii //weight: 2
        $x_2_14 = "iKwxJDSk0uJsmK6vtggUXN8pDvb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBot_GQ_2147749193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.GQ!MTB"
        threat_id = "2147749193"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 00 66 c7 [0-2] 73 00 66 c7 [0-2] 77 00 66 c7 [0-2] 68 00 66 c7 [0-2] 6f 00 66 c7 [0-2] 6f 00 66 c7 [0-2] 6b 00 66 c7 [0-2] 2e 00 66 c7 [0-2] 64 00 66 c7 [0-2] 6c 00 66 c7 [0-2] 6c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 5b 8d 0c [0-2] 8b [0-2] f7 [0-2] 8b 44 [0-2] 8a [0-2] 30 01 46 3b 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_GQ_2147749193_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.GQ!MTB"
        threat_id = "2147749193"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 40 68 00 10 00 00 57 6a 00 ff d3}  //weight: 1, accuracy: High
        $x_1_2 = "\\DLLPORTABLEX86\\32\\Release\\dll32smpl.pdb" ascii //weight: 1
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_1_4 = "KrasIodW" ascii //weight: 1
        $x_1_5 = "assb1" ascii //weight: 1
        $x_1_6 = "imit4" ascii //weight: 1
        $x_1_7 = "ltridp" ascii //weight: 1
        $x_1_8 = "1.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_DC_2147749293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DC!MTB"
        threat_id = "2147749293"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8b c1 bf ?? ?? ?? ?? f7 f7 8b 7c 24 0c 8a 04 39 8a 54 14 ?? 32 c2 88 04 39 41 81 f9 e0 07 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 5b 8d 0c 07 8b c7 f7 f3 8b 44 24 10 8a 04 02 30 01 47 3b 7c 24 18 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBot_DC_2147749293_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DC!MTB"
        threat_id = "2147749293"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Crypter.dll" ascii //weight: 1
        $x_1_2 = "Crypter.pdb" ascii //weight: 1
        $x_1_3 = "dKERNEL32.dll" ascii //weight: 1
        $x_1_4 = ".00cfg" ascii //weight: 1
        $x_1_5 = "_mfEwVKAGOAT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_DC_2147749293_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DC!MTB"
        threat_id = "2147749293"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hukmnjufewgjoghuigohvbtysoghgty" ascii //weight: 1
        $x_1_2 = "WriteProcessMemory" ascii //weight: 1
        $x_1_3 = "VirtualAllocEx" ascii //weight: 1
        $x_1_4 = "TerminateProcess" ascii //weight: 1
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_HA_2147749887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.HA!MTB"
        threat_id = "2147749887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c1 33 d2 f7 f3 41 8a 44 55 00 30 44 31 ff 3b cf 75}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 11 c1 c8 0d 41 03 c2 80 79 ff 00 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_HA_2147749887_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.HA!MTB"
        threat_id = "2147749887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 12 33 db 43 2b df 0f af d8 8b 45 0c 89 4d f8 8b 0d ?? ?? ?? ?? 2b d9 6b c9 05 03 1d ?? ?? ?? ?? 03 5d fc 03 d8 8b 45 f4 0f b6 04 30 03 c2 33 d2 f7 35 ?? ?? ?? ?? 2b d1 03 d7 03 15 ?? ?? ?? ?? 8a 04 32 30 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_KVP_2147749923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.KVP!MTB"
        threat_id = "2147749923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 08 0f b7 0c 50 8b 55 0c 03 55 fc 0f b6 02 33 c1 8b 4d 0c 03 4d fc 88 01}  //weight: 2, accuracy: High
        $x_2_2 = {8b 44 24 14 5b 8d 0c 06 8b c6 f7 f3 8b 44 24 0c 8a 04 02 30 01}  //weight: 2, accuracy: High
        $x_2_3 = {8b 45 f0 6a 26 33 d2 5f 03 c8 f7 f7 8a 44 15 9c 30 01}  //weight: 2, accuracy: High
        $x_1_4 = {69 c0 fd 43 03 00 83 ec 50 56 a3 05 00 a1}  //weight: 1, accuracy: Low
        $x_1_5 = {30 04 33 81 ff 1e 10 00 00 75 05 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_TrickBot_HB_2147750186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.HB!MTB"
        threat_id = "2147750186"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 7d 10 2b f9 53 50 8b 01 33 02 52 8b d0 51 03 cf 51 58 89 10 59 5a 42 42 58 42 42 3b 55 08 72 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_HB_2147750186_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.HB!MTB"
        threat_id = "2147750186"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 99 f7 bd ?? ?? ?? ?? 8b 45 10 03 85 ?? ?? ?? ?? 8a 08 32 8c 15 ?? ?? ?? ?? 8b 55 10 03 95 ?? ?? ?? ?? 88 0a 8b 85 ?? ?? ?? ?? 83 c0 01 89 85 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_BK_2147750884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.BK!MTB"
        threat_id = "2147750884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 99 b9 40 34 01 00 f7 f9 8b 45 ?? 33 c9 8a 0c 10 89 4d ?? 8b 55 ?? 03 55 ?? 0f be 02 50 8b 4d ?? 51 e8 ?? ?? ?? ?? 83 c4 08 8b 55 ?? 03 55 ?? 88 02 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_EA_2147751457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.EA!MTB"
        threat_id = "2147751457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 02 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 2b d8 03 1d ?? ?? ?? ?? 8b 55 0c 8a 04 0a 32 c3 8b 4d fc 8b 11 8b 4d 0c 88 04 11 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_SR_2147751670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.SR!MTB"
        threat_id = "2147751670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 ce 83 e6 03 75 ?? 8b 5d 10 66 01 da 6b d2 02 c1 ca 03 89 55 10 30 10 40 e2 ?? c9}  //weight: 1, accuracy: Low
        $x_1_2 = {83 7d f8 01 7e ?? 8b 4d f8 0f b6 91 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 8b 45 f8 88 ?? ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8d 44 0a a1 a3 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_BC_2147752101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.BC!MTB"
        threat_id = "2147752101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 04 2f 8a d3 8a c8 f6 d2 f6 d1 0a d1 0a d8 22 d3 88 17 83 c7 01 83 6c 24 ?? 01 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 01 99 b9 ?? ?? ?? ?? f7 ?? 8b 4c 24 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b f2 0f b6 04 0e 03 c3 99 bb ?? ?? ?? ?? f7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_AR_2147752412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.AR!MSR"
        threat_id = "2147752412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OnscreenKeyboard.EXE" wide //weight: 1
        $x_1_2 = "Hide the onscreen kayboard+Terminate the Onscreen Keyboard application" wide //weight: 1
        $x_1_3 = "FTCpOhyrHahTF" ascii //weight: 1
        $x_1_4 = "OnscreenKeyboard MFC Application" wide //weight: 1
        $x_1_5 = "GetProcAddress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_DSP_2147752767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DSP!MTB"
        threat_id = "2147752767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be 0c 10 8b 55 f4 0f b6 82 ?? ?? ?? ?? 33 c1 8b 4d f4 88 81 ?? ?? ?? ?? eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_PVF_2147754584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.PVF!MTB"
        threat_id = "2147754584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 44 34 18 81 e1 ff 00 00 00 03 c1 b9 14 02 00 00 99 f7 f9 8a 03 8d 4c 24 10 c7 84 24 34 02 00 00 ff ff ff ff 8a 54 14 18 32 c2 88 03}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_PVA_2147755898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.PVA!MTB"
        threat_id = "2147755898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8b ec 83 ec 14 c7 45 f0 ?? ?? ?? ?? c7 45 fc 00 00 00 00 eb ?? 8b 45 fc 83 c0 01 89 45 fc 81 7d fc ff 2b 00 00 0f 8d ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 68}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_PRB_2147757067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.PRB!MTB"
        threat_id = "2147757067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 68 00 30 00 00 53 6a 00 ff d5 8b 77 54 8b d8 8b 44 24 5c 33 c9 89 44 24 14 8b d3 33 c0 89 5c 24 18 40 89 44 24 24 85 f6 74}  //weight: 1, accuracy: High
        $x_1_2 = {8b 51 f8 48 8b 31 03 d3 8b 69 fc 03 f7 89 44 24 5c 85 ed 74 0f 8a 06 88 02 42 46 83 ed 01 75 f5 8b 44 24 5c 83 c1 28 85 c0 75 d5}  //weight: 1, accuracy: High
        $x_1_3 = {e8 00 00 00 00 58 89 c3 05 ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 68 ?? ?? ?? ?? 50 e8 04 00 00 00 83 c4 14 c3 83 ec 48 83 64 24 18 00 b9 ?? ?? ?? ?? 53 55 56 57 33 f6 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_DSL_2147759190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DSL!MTB"
        threat_id = "2147759190"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 45 89 8a 4d 88 8a 55 89 c0 e8 04 c0 e1 02 0a c1 8a 4d 8a 88 06 8a c1 c0 e8 02 c0 e2 04 0a c2 46 c0 e1 06 0a 4d 8b 88 06 46 88 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_DSM_2147759191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DSM!MTB"
        threat_id = "2147759191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 f8 74 ?? 33 d2 f7 75 fc 8b 45 f8 8a 0c 55 [0-4] 30 0c 18 40 3b c6 89 45 f8 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_DSN_2147759200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DSN!MTB"
        threat_id = "2147759200"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f0 33 d2 b9 08 00 00 00 f7 f1 8b 45 f8 0f be 0c 10 8b 55 f0 0f b6 82 [0-4] 33 c1 8b 4d f0 88 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_DSO_2147759201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DSO!MTB"
        threat_id = "2147759201"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 0f b6 84 33 [0-4] 30 84 1c [0-4] 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 68 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_DSQ_2147759272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DSQ!MTB"
        threat_id = "2147759272"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f0 33 d2 b9 ?? 00 00 00 f7 f1 8b 45 f8 0f be 0c 10 8b 55 f0 0f b6 82 ?? ?? ?? ?? 33 c1 8b 4d f0 88 81 ?? ?? ?? ?? 8b 55 f0 83 c2 01 89 55 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_DSR_2147759282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DSR!MTB"
        threat_id = "2147759282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 2c a1 ?? ?? ?? ?? 33 c5 89 45 fc 33 c0 0f b6 88 ?? ?? ?? ?? 81 f9 ff 00 00 00 0f 87 ?? ?? ?? ?? ff 24 8d}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 05 2e 00 00 0f 83 ?? ?? ?? ?? c6 80 ?? ?? ?? ?? 00 e9 ?? ?? ?? ?? c6 80 ?? ?? ?? ?? 01 e9 ?? ?? ?? ?? c6 80 ?? ?? ?? ?? 02 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_DSS_2147759286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DSS!MTB"
        threat_id = "2147759286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8b ec 51 53 56 6a 04 33 c0 ba 05 2e 00 00 5b 0f b6 88 ?? ?? ?? ?? 81 f9 ff 00 00 00 0f 87 ?? ?? ?? ?? ff 24 8d ?? ?? ?? ?? c6 80 ?? ?? ?? ?? 00 e9 ?? ?? ?? ?? c6 80 ?? ?? ?? ?? 01 e9 ?? ?? ?? ?? c6 80 ?? ?? ?? ?? 02 e9}  //weight: 2, accuracy: Low
        $x_1_2 = {55 8b ec 83 ec 24 a1 ?? ?? ?? ?? 33 c5 89 45 fc c7 45 e0 ?? ?? ?? ?? c7 45 f0 00 00 00 00 c7 45 dc 00 00 00 00 c7 45 f0 00 00 00 00 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 f0 83 c0 01 89 45 f0 81 7d f0 05 2e 00 00 0f 83 ?? ?? ?? ?? 8b 4d f0 0f b6 91 ?? ?? ?? ?? 89 55 e8 81 7d e8 ff 00 00 00 0f 87}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_TrickBot_DST_2147759307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DST!MTB"
        threat_id = "2147759307"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 fc 00 00 00 00 c7 45 e8 00 00 00 00 c7 45 fc 00 00 00 00 eb 09 8b 45 fc 83 c0 01 89 45 fc 81 7d fc 05 2e 00 00 0f 83 ?? ?? ?? ?? 8b 4d fc 0f b6 91 ?? ?? ?? ?? 89 55 f0 81 7d f0 ff 00 00 00 0f 87 ?? ?? ?? ?? 8b 45 f0 ff 24 85 07 00 c7 45 ec}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 f8 00 00 00 00 c7 45 e8 00 00 00 00 c7 45 f8 00 00 00 00 eb 09 8b 45 f8 83 c0 01 89 45 f8 81 7d f8 05 2e 00 00 0f 83 ?? ?? ?? ?? 8b 4d f8 0f b6 91 ?? ?? ?? ?? 89 55 f0 81 7d f0 ff 00 00 00 0f 87 ?? ?? ?? ?? 8b 45 f0 ff 24 85 07 00 c7 45 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBot_RTB_2147760351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.RTB!MTB"
        threat_id = "2147760351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Stup windows defender hahah" ascii //weight: 1
        $x_1_2 = "ZM8#9auOMcA+pH<" ascii //weight: 1
        $x_1_3 = "CryptAcquireContextW" ascii //weight: 1
        $x_1_4 = "CryptImportKey" ascii //weight: 1
        $x_1_5 = "CryptEncrypt" ascii //weight: 1
        $x_1_6 = "GetSystemMetrics" ascii //weight: 1
        $x_1_7 = "GetMonitorInfoA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_DB_2147760417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DB!MTB"
        threat_id = "2147760417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 ce 81 e1 ff 00 00 80 88 1d ?? ?? ?? ?? 79 ?? 49 81 c9 00 ff ff ff 41 8a 89 ?? ?? ?? ?? 30 0c 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_DB_2147760417_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DB!MTB"
        threat_id = "2147760417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8d 46 01 f7 35 ?? ?? ?? ?? 43 8b f2 8a 04 0e 88 45 ff 0f b6 c0 03 c7 33 d2 f7 35 ?? ?? ?? ?? 8b fa 0f b6 04 0f 8a 55 ff 88 04 0e 88 14 0f 0f b6 04 0e 0f b6 d2 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 45 0c 0f b6 14 0a 02 15 ?? ?? ?? ?? 30 54 03 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_PSA_2147760419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.PSA!MTB"
        threat_id = "2147760419"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c6 33 d2 b9 2b 00 00 00 f7 f1 8a 04 3e 8a 14 2a 32 c2 88 04 3e 46 3b f3 75 db}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_DSU_2147760817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DSU!MTB"
        threat_id = "2147760817"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5d 00 8b 44 24 ?? 83 c4 30 8a 54 14 ?? 32 da 88 5d}  //weight: 1, accuracy: Low
        $x_1_2 = "TS?3?IP|SC6oV%S}WZi2TJy|" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBot_DSV_2147760889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DSV!MTB"
        threat_id = "2147760889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 84 14 ?? ?? ?? ?? 8b 54 24 ?? 32 02 88 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = "PkscXx19y6HKZzu6m~yMrYuDpiFdr611|C8b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBot_DSW_2147761640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DSW!MTB"
        threat_id = "2147761640"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 3c 38 30 39 03 ce 03 fe eb ?? 33 ff 3b ca 72 05 00 83 ff ?? 7f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_DSX_2147762107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DSX!MTB"
        threat_id = "2147762107"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 0e 0f b6 d2 03 c2 99 f7 fb 8a 04 0a 8b 54 24 ?? 32 04 3a 88 07}  //weight: 1, accuracy: Low
        $x_1_2 = "*?Lp7EbO87BzmKD#CWz@hFAn}uOpmu~*wLBde$h4D}t01Zve*o5IW0VD6u" ascii //weight: 1
        $x_1_3 = "47ynH8v45zH|sfMs?z{SeTCerU6FAFwcHv0cAYzpAxHTK#hDSea?LLxRL8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBot_GC_2147762167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.GC!MTB"
        threat_id = "2147762167"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 01 8b 4c 24 ?? 32 54 0c ?? 88 10 40 89 44 24 ?? 8b 44 24 ?? 48 89 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = "Ha5XTkFWcrqOgTK5eD0uwHJgI42NrpUnDm9LNXf83oThMLEx1k2l8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBot_DD_2147762733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DD!MTB"
        threat_id = "2147762733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hykg1BH~48#ilYr" ascii //weight: 1
        $x_1_2 = "LockResource" ascii //weight: 1
        $x_1_3 = "WriteFile" ascii //weight: 1
        $x_1_4 = "PostMessageA" ascii //weight: 1
        $x_1_5 = "GetCapture" ascii //weight: 1
        $x_1_6 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_DE_2147762814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DE!MTB"
        threat_id = "2147762814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d1 02 d2 8a c5 c0 f8 04 02 d2 24 03 02 c2 88 45}  //weight: 1, accuracy: High
        $x_1_2 = {8a d0 c0 fa 02 8a cd c0 e1 04 80 e2 0f 32 d1 8b 4d ?? c0 e0 06 02 45 ?? 88 55 ?? 66 8b 55 ?? 66 89 11 88 41 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_RT_2147762868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.RT!MTB"
        threat_id = "2147762868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 f9 80 c2 64 85 f6 76 ?? 8b 45 ?? 8a 08 32 ca 02 ca 88 08 40 4e 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_RT_2147762868_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.RT!MTB"
        threat_id = "2147762868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 3b eb 7e ?? 8b 54 24 ?? 8d 4c 2a ?? 8a 11 88 ?? ?? ?? ?? ?? 40 49 3b c5 7c ?? 8d 45 ?? 83 f8 3e 88 9d ?? ?? ?? ?? 7d}  //weight: 1, accuracy: Low
        $x_1_2 = "?oGb!do$Pb#+iQJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_RT_2147762868_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.RT!MTB"
        threat_id = "2147762868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 04 0e 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 0f af 35 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 0f af 3d ?? ?? ?? ?? 0f af 3d ?? ?? ?? ?? 8b 5d ec 2b df}  //weight: 1, accuracy: Low
        $x_2_2 = "whoami.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_RT_2147762868_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.RT!MTB"
        threat_id = "2147762868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 8a 04 37 81 e1 ff 00 00 00 03 c1 f7 35 ?? ?? ?? ?? 8b ea ff 15 ?? ?? ?? ?? 85 c0 74 ?? ff 15 ?? ?? ?? ?? 8a 14 2e 8b 44 24 ?? 8b 6c 24 ?? 8a 0c 28 32 ca 88 0c 28 8b 4c 24 ?? 40 3b c1 89 44 24 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_RT_2147762868_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.RT!MTB"
        threat_id = "2147762868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 02 f3 ab 8b ca 83 e1 03 f3 aa 8d 45 ?? 89 5d ?? 50 53 ff 75 ?? 6a 4c 68 b8 51 47 00 ff 75 ?? ff 55 ?? 85 c0 74 ?? 8b 45 ?? ff 30 50 ff 75 ?? 53 6a 01 53 ff 75 ?? ff 55 ?? 85 c0 0f 95 c0 eb ?? 32 c0}  //weight: 1, accuracy: Low
        $x_1_2 = "pM2wt0b414!nfra" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_RT_2147762868_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.RT!MTB"
        threat_id = "2147762868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c2 2b 05 ?? ?? ?? ?? 8b 55 ?? 8b 75 ?? 8a 0c 0a 32 0c 06 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 75}  //weight: 1, accuracy: Low
        $x_1_2 = "Qg<G2Olq+%xaHySmzWohEHke)B*C26AiK(PL*b8306C@<o08P1r0zPjP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_RT_2147762868_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.RT!MTB"
        threat_id = "2147762868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 03 f2 25 ff 00 00 00 33 d2 03 c6 f7 f7 8b f2 8a 04 2e 88 01 8b 44 24 ?? 88 1c 2e 8b 3d ?? ?? ?? ?? 40 41 3b c7 89 44 24 ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = "(3(an91Xp7pN&QG<fKC^HtB&tsi7rL5)bttpWjDls28JdY(JNvEiSaWbrQUZkT8JyA<HbFZx(jNKNC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_RT_2147762868_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.RT!MTB"
        threat_id = "2147762868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 f7 35 ?? ?? ?? ?? 8b ?? ?? 89 ?? ?? 8b ?? ?? 8d 0c 02 8a c3 f6 eb 8b ?? ?? 8a 1c 33 2a d8 30 19 42 3b ?? ?? 89 ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = "_KErGZ02@?UVJER>7+HPXhnKN2mQe$u#nbvc03LYYQ>W)s_$^q(J)9WY5LJ6BZv?YKm6gf*zqr3khC_M)t$i8xI@x#lvgVJ^mUGs2Q5rR)hYeF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_RT_2147762868_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.RT!MTB"
        threat_id = "2147762868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AfxOldWndProc423" ascii //weight: 1
        $x_1_2 = "http://www.xxx.com/1.jpg" ascii //weight: 1
        $x_1_3 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_4 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_6 = "GetTickCount" ascii //weight: 1
        $x_1_7 = "PostMessageA" ascii //weight: 1
        $x_1_8 = "GetSystemMetrics" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_RT_2147762868_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.RT!MTB"
        threat_id = "2147762868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c1 01 89 4d ?? 8b 55 ?? 3b 15 ?? ?? ?? ?? 73 ?? 8b 45 ?? 03 45 ?? 8a 4d ?? 88 08 8b 45 ?? 33 d2 f7 75 ?? 8b 45 ?? 03 45 ?? 8b 4d ?? 8a 14 11 88 10 eb}  //weight: 1, accuracy: Low
        $x_1_2 = "O>y1*Vt<_yXP*DTDw7@*2?0Cm+CG>@6nVMo0TuH7@$h0Z!Ft>oiGGGQt(*5Ahx*q" ascii //weight: 1
        $x_1_3 = "nhWX)rNLmb*7#P9*ttsQ?#lZSdLm849J#WDL5ISWpsp51T?Kh41XVmwI7<6rJgg_(Z5rkDHEI_q<d_qacgWKM!oR>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_TrickBot_DSY_2147762957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DSY!MTB"
        threat_id = "2147762957"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 01 8b 45 f8 03 45 f4 33 c9 8a 08 33 d1 a1 ?? ?? ?? ?? 8b 08 8b 45 18 88 14 08}  //weight: 1, accuracy: Low
        $x_1_2 = "4XV%FN|kL8L9PTS{lH$xjU1~qeE~XJyxeidzDFOS7~GlAnEbhEDnJY9tTlSN8hGHxmS0?54*N}z~~PIfngxytq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrickBot_I_2147766703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.I!MTB"
        threat_id = "2147766703"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 45 e6 30 44 0d ?? 41 83 f9 ?? 72}  //weight: 10, accuracy: Low
        $x_10_2 = {73 05 8a 4d 0f 00 30 4c 05 ?? 40 83 f8 ?? ?? ?? ?? ?? ?? eb f1}  //weight: 10, accuracy: Low
        $x_1_3 = {89 75 bc 89 4d b0 c7 45 ?? 74 00 2d 00 c7 45 ?? 43 00 6f 00 c7 45 ?? 6f 00 6b 00 c7 45 ?? 69 00 65 00 c7 45 ?? 3a 00 00 00 66 89 45 f4}  //weight: 1, accuracy: Low
        $x_1_4 = {33 c0 66 89 4d c4 c7 45 ?? f6 35 af 35 c7 45 ?? c1 35 ed 35 c7 45 ?? ed 35 e9 35 c7 45 ?? eb 35 e7 35 c7 45 ?? b8 35 82 35 66 89 45 f4 66 31 4c 45 c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_J_2147766704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.J!MTB"
        threat_id = "2147766704"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XYXEQX8dMYWKgX8KMNQpqCL" ascii //weight: 1
        $x_1_2 = "gMofH.dll" ascii //weight: 1
        $x_1_3 = {43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_K_2147766705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.K!MTB"
        threat_id = "2147766705"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Xvaultcli.dll" wide //weight: 1
        $x_1_2 = "SysListView32" wide //weight: 1
        $x_1_3 = "atl.dll" wide //weight: 1
        $x_1_4 = {53 52 56 44 41 54 41 2e 64 6c 6c 00 43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 4e 65 74 53 65 72 76 65 72 53 74 61 72 74 00 4e 65 74 53 65 72 76 65 72 53 74 6f 70 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {8b c1 8b d1 03 c6 3b fe 76 08 3b f8 0f 82 ?? ?? ?? ?? 83 f9 ?? 0f 82 ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 73 13 0f ba 25 ?? ?? ?? ?? 01 0f 82 ?? ?? ?? ?? e9 ?? ?? ?? ?? 0f ba 25 ?? ?? ?? ?? 01 73 09 f3 a4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_A_2147766708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.A!ibt"
        threat_id = "2147766708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\rdpscan.pdb" ascii //weight: 1
        $x_2_2 = {43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 52 65 6c 65 61 73 65 00 53 74 61 72 74}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_DY_2147778331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DY!MTB"
        threat_id = "2147778331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 19 03 d6 0f b6 c3 03 c2 33 d2 f7 f7 8b 7c 24 18 45 41 8b f2 8a 04 3e 88 41 ff 88 1c 3e}  //weight: 1, accuracy: High
        $x_1_2 = {45 8b f2 8a 1c 0e 33 d2 0f b6 c3 03 c7 f7 35 ?? ?? ?? ?? 8b fa 8a 04 0f 88 04 0e 88 1c 0f 0f b6 04 0e 0f b6 d3 03 c2 33 d2 f7 35 [0-17] 8a c3 f6 eb 8a 14 0a 2a d0 8b 44 24 18 30 54 28 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_DX_2147778542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.DX!MTB"
        threat_id = "2147778542"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f8 00 00 00 2b [0-18] 6b ?? 29 8b ?? c1 e2 06 [0-4] 8b 54 ?? 3c [0-4] 2b ?? 8b ?? ?? 78 03 [0-3] 8b [0-2] 24 8b [0-2] 20 [0-4] 8d [0-8] 8b ?? 1c 8b ?? 18 [0-8] 03 ?? 03 ?? 03 ?? 03}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 8b [0-21] c1 ?? 0d 3c 61 0f be c0 7c 03 83 e8 20 [0-4] 03 [0-4] 8a ?? 84 c0 75 ea 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_EB_2147778634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.EB!MTB"
        threat_id = "2147778634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b da 8b fa 89 5d ?? 89 4d 08 8b ff 8a 0c 3b 80 f1 20 8b c7 3b fe 73 1b 8d 64 ?? ?? 8a d8 2a da 80 e3 20 32 18 32 d9 88 18 03 45 ?? 3b c6 72 ec 8b 5d ?? 47 ff 4d 08 75}  //weight: 1, accuracy: Low
        $x_1_2 = {23 d1 8a 06 88 07 8a 46 01 88 47 01 8a 46 02 c1 e9 02 88 47 02 83 c6 03 83 c7 03 83 f9 08 72 [0-21] 23 d1 8a 06 88 07 8a 46 01 c1 e9 02 88 47 01 83 c6 02 83 c7 02 83 f9 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_AL_2147785370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.AL!MTB"
        threat_id = "2147785370"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "asRuler" ascii //weight: 1
        $x_1_2 = "frmHighScore" ascii //weight: 1
        $x_1_3 = "http://www.wordsmyth.net/cgi-bin/search.cgi" wide //weight: 1
        $x_1_4 = "WORDLIST.mdb" wide //weight: 1
        $x_1_5 = "high.txt" wide //weight: 1
        $x_1_6 = {70 00 6f 00 77 00 65 00 72 00 77 00 6f 00 72 00 64 00 5c 00 50 00 6f 00 77 00 65 00 72 00 57 00 6f 00 72 00 64 00 2e 00 76 00 62 00 70}  //weight: 1, accuracy: High
        $x_1_7 = "GetRS" ascii //weight: 1
        $x_1_8 = "PowerWord.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_EI_2147794935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.EI!MTB"
        threat_id = "2147794935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f0 03 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 03 c1 2b 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 2b c2 2b 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 8b 4d 08 0f b6 14 01 8b 45 0c 03 45 f4 0f b6 08 33 ca 8b 55 0c 03 55 f4 88 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_EL_2147795125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.EL!MTB"
        threat_id = "2147795125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 11 8b c2 8b 4d 08 03 4d f0 33 d2 8a 11 03 c2 33 d2 f7 35 ?? ?? ?? ?? 89 55 f8 8b 45 ec 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 4d f8 03 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 03 ca 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 8b 55 0c 8b 75 08 8a 04 02 32 04 0e 8b 4d ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_EJ_2147795316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.EJ!MTB"
        threat_id = "2147795316"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c0 2b d0 8b c1 8d 14 51 88 0c 3a 33 d2 f7 f6 a1 ?? ?? ?? ?? 8b e8 0f af e8 a1 ?? ?? ?? ?? 03 c0 2b e8 8b 44 24 10 41 8d 04 68 8a 14 1a 88 54 08 ff a1 ?? ?? ?? ?? 3b c8 72}  //weight: 1, accuracy: Low
        $x_1_2 = {88 04 3a a1 ?? ?? ?? ?? 8d 0c 40 8d 54 09 03 8b 0d ?? ?? ?? ?? 0f af d0 83 c2 03 0f af d0 a1 ?? ?? ?? ?? 03 ea 2b c1 8a 4c 24 1c 8d 04 c0 03 c5 46 88 0c 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_HC_2147795413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.HC!MTB"
        threat_id = "2147795413"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 83 c0 01 33 d2 f7 35 ?? ?? ?? ?? 89 55 fc 8b 55 08 03 55 fc 0f b6 02 03 45 ec 33 d2 f7 35 ?? ?? ?? ?? 89 55 ec 8b 45 08 03 45 fc 8a 08 88 4d fb 8b 55 08 03 55 fc 8b 45 08 03 45 ec 8a 08 88 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_EN_2147795983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.EN!MTB"
        threat_id = "2147795983"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 11 03 c2 33 d2 f7 35 ?? ?? ?? ?? 89 55 f8 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 4d ec 2b c8 2b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 8b 55 f8 03 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 2b d0 2b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 03 d0 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 03 45 08 8b 75 0c 8a 0c 0e 32 0c 10}  //weight: 1, accuracy: Low
        $x_1_2 = "whoami.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_FE_2147797610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.FE!MTB"
        threat_id = "2147797610"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d f0 03 4d ec 0f be 11 81 f2 e0 00 00 00 88 55 eb 8b 45 08 03 45 ec 89 45 e4 8b 4d e4 3b 4d f8 73 2d 8b 55 e4 0f b6 02 0f b6 4d eb 33 c1 8b 55 e4 2b 55 08 0f b6 ca 81 e1 e0 00 00 00 33 c1 8b 55 e4 88 02 8b 45 e4 03 45 f4 89 45 e4 eb cb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_QW_2147799573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.QW!MTB"
        threat_id = "2147799573"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "yimpjfdl.dll" ascii //weight: 3
        $x_3_2 = "DllRegisterServer" ascii //weight: 3
        $x_3_3 = "akfqqjtouyo" ascii //weight: 3
        $x_3_4 = "alqxdcvfbhj" ascii //weight: 3
        $x_3_5 = "REkju5rkw" ascii //weight: 3
        $x_3_6 = "InterlockedFlushSList" ascii //weight: 3
        $x_3_7 = "DecodePointer" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_NA_2147929882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.NA!MTB"
        threat_id = "2147929882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c6 00 40 c6 40 01 6b c6 40 02 72 c6 40 03 2d c6 40 04 4a c6 40 05 02}  //weight: 2, accuracy: High
        $x_1_2 = {89 e6 8d 48 ff 0f af c8 89 c8 83 f0 fe 85 c8}  //weight: 1, accuracy: High
        $x_1_3 = "@W@KrasIodW" ascii //weight: 1
        $x_1_4 = "KrasIodW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_MKZ_2147932056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.MKZ!MTB"
        threat_id = "2147932056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 c1 03 32 d7 88 54 24 02 8a e0 88 44 24 ?? 80 f4 c0 22 e0 c0 e8 06 0a c6 83 c7 fd 88 44 24 ?? 88 64 24 04 0f b6 c3 8b dd 0f b6 04 03 88 06 0f b6 44 24 02}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickBot_MKP_2147932419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickBot.MKP!MTB"
        threat_id = "2147932419"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 54 24 58 8d 7c 24 03 8d 74 24 43 8b df 03 ea 3b de 0f 43 df 8a 0b 43 30 0a 42 3b d5 72 f1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

