rule Trojan_Win32_Wabot_2147807389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wabot.lmnq!MTB"
        threat_id = "2147807389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wabot"
        severity = "Critical"
        info = "lmnq: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "software\\microsoft\\windows\\currentversion\\app paths\\winzip32.exe" ascii //weight: 1
        $x_1_2 = "software\\microsoft\\windows\\currentversion\\app paths\\WinRAR.exe" ascii //weight: 1
        $x_1_3 = "FUCK" ascii //weight: 1
        $x_1_4 = "system.ini" ascii //weight: 1
        $x_1_5 = "C:\\rar.bat" ascii //weight: 1
        $x_1_6 = "C:\\zip.bat" ascii //weight: 1
        $x_1_7 = "sIRC4.exe" ascii //weight: 1
        $x_1_8 = "C:\\marijuana.txt" ascii //weight: 1
        $x_1_9 = "uk.undernet.org" ascii //weight: 1
        $x_1_10 = "TWarBot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Wabot_DW_2147853115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wabot.DW!MTB"
        threat_id = "2147853115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TuICz58a](!!+$11[&kG8f!!\"!5*8*m&u\"=1|%!\";.=$0h8U&hG&ni;\"\"\"^tT2+aqF0}$q1^\"^>i]fVZOn4U7" ascii //weight: 1
        $x_1_2 = {6c a3 6d 43 43 34 66 39 49 49 35 30 2a 66 7e 22 21 74 36 24 72 69 69 2a 6d 30 77 3c 22 3b 5f 43 59 6f 54 6d 54 2b 3d 6f 25 21 4a 5e 22 22 22 25 56 53 67 41 50 30 78 5a 75 6f 37 5e 3b 22 22 3b 29 65 6e 25 43 30 44 62 75 7b 68 25 5e 22 5c 6f 37 74 49 71 44 70 7a 73 54 74 5e}  //weight: 1, accuracy: High
        $x_1_3 = "v5Zm9r*a5IqZ&^C\"<eV0+CkZaTl.;<Lry04as9t13?wQDDSForn0n:^.^^uI8e0JtxGLm" ascii //weight: 1
        $x_1_4 = "^tTnt?2mOszzqSc:^^!hmk6]i99Oo.;_Xb*50Lxd01;\"TebbeV0smD" ascii //weight: 1
        $x_1_5 = {55 a3 32 61 57 78 73 44 46 2a 50 20 2e 20 2e 2e 21 65 50 44 51 44 51 46 44 4f 75 5d 2e 20 20 20 4f 49 6f 32 75 2b 75 54 34 34 37 2e 20 20 20 20 2e 21 73 50 57 64 6c 2b 37 6e 5b 49 61 2e 20 2e 29 47 57 57 67 4f a3 24 4c 47}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Wabot_DX_2147853275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wabot.DX!MTB"
        threat_id = "2147853275"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 2a 64 6b 33 2b 2b 2a 54 36 56 3d 20 20 20 7c 59 6e 43 29 22 74 49 34 2a 30 2b 2e 2e 2e 20 20 20 20 20 20 2e 69 38 32 5d 77 77 36 61 50 70 78 36 20 20 2e 2e 2e 3c 38 41 71 46 68 73 75 a3 39 75 46 20 2e 20 20 2a 50 53 23 71 a3 31 2b 21 7e 3c}  //weight: 1, accuracy: High
        $x_1_2 = {61 4f 37 2b 49 73 78 51 46 56 3d 2e 20 20 20 2e 22 24 64 64 64 44 65 59 24 a3 76 51 2e 20 20 2e 65 46 51 44 35 25 6b 50 68 33 3e 2e 20 20 20 20 2e 59 5a 65 71 51 50 5a 55 30 36 75 7a}  //weight: 1, accuracy: High
        $x_1_3 = {57 78 35 30 47 47 73 24 43 61 22 5e 3d 2a 68 34 78 68 79 58 57 41 78 ac 5e 2d 4a 49 49 2a 67 57 35 32 43 5e 2e 20 20 2e 5e 6e 79 24 7e 3a 2e 2e 2e 20 2e 20 20 22 39 73 43 25 5d 75 47 6e 62 35 76 2e 2e 2e 20 7e 38 6b 6b 6e 79 36 75 24 24 32}  //weight: 1, accuracy: High
        $x_1_4 = {69 56 a3 75 49 72 a3 73 59 35 79 2e 2e 2e 20 2e 3d 4f 43 32 33 63 33 63 66 49 35 34 22 6b 34 56 3f 28 36 39 74 2e 29 67 39 49 24 4a 56 55 69 21 74 5b 20 2e 20 2e 2e 22 43 43 a3 54 79 4c 2a 5a 68 65 34}  //weight: 1, accuracy: High
        $x_1_5 = {3d 67 59 44 46 53 51 55 67 44 6a 2d 47 6b 4b 35 6f 56 68 46 4a 21 2e 20 22 21 39 6d 2a 4a 61 50 61 a3 3f 2e 20 2e 20 20 20 20 2e 3b 21 4a 61 75 24 55 46 55 2a 61 2a 6e 24 79 31 56 4f 62 7e 2e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Wabot_GME_2147888137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wabot.GME!MTB"
        threat_id = "2147888137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "marijuana.txt" ascii //weight: 1
        $x_1_2 = "qUFDZPShpptcFQq" ascii //weight: 1
        $x_1_3 = "bKDPmfzhepUQZh" ascii //weight: 1
        $x_1_4 = "Gxebk4LheAAqbPPPFPZPZQk$" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Wabot_GME_2147888137_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wabot.GME!MTB"
        threat_id = "2147888137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tWx50GGs$Ca" ascii //weight: 1
        $x_1_2 = "Jc3Jc3rcccrfJ3ccfffJ3c32Jfrc2ffr3cJ2" ascii //weight: 1
        $x_1_3 = {64 30 34 6b 4f 35 56 55 4c 23 41 46 46 4c 38 26 59 4f 46 46 63 3d 73 61 6e a3 43 76 2a 71 5a 61 63}  //weight: 1, accuracy: High
        $x_1_4 = "gYDFSQUgDj-GkK5oVhFJ!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Wabot_MB_2147896636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wabot.MB!MTB"
        threat_id = "2147896636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7d fa 13 27 e0 94 d7 c0 e0 42 f8 91 3f 8e a1 6b 94 b3 11 d2 df 6b 68 92 91 16 0c 0b 4b 56 6d 8b}  //weight: 1, accuracy: High
        $x_1_2 = {c6 97 55 3a ab 26 13 6c 4b c8 25 5d 81 02 35 a2 29 70 95 eb f7 e3 7f c9 a7 2f c8 9a b7 d5 de db}  //weight: 1, accuracy: High
        $x_1_3 = {35 f0 21 6f 57 18 05 ac d8 27 8b 2a 57 04 f5 ba 34 e7 d0 f6 aa c4 a4 4a 1b bf 02 74 d3 e1 a7 d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Wabot_MA_2147901377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wabot.MA!MTB"
        threat_id = "2147901377"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {be d6 ae f1 81 ed e5 5b de 26 d8 5b 9f 1a aa 2a 4f 67 8d 12 bd 96 78 f3 3a c9 a5 a1 31 2d 0f 54 fd 89 73 8e 0e 77 84 1e c3 06 5c 3e 8d e1 5a df}  //weight: 10, accuracy: High
        $x_10_2 = {e4 88 09 4e 5b b7 58 67 7e 1b 7c 33 b6 69 e9 50 b1 94 fe 8a a9 b7 c9 77 23 2d ae e0 b5 eb 55 28 b6 5e 38 1d f4 64 a2 d2 c8 20 0e 86 25 be 34 ad 83 74 26 90 bc 41 50 39 3c 44 50 80 14 ab d4 83}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Wabot_DY_2147908214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wabot.DY!MTB"
        threat_id = "2147908214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {d0 7e 6b f3 04 dc 48 36 d9 e9 a6 52 c6 1e 04 6d 5b 35 89 73 fd a3 ba fe 41 14 67 03 53 10 41 0f 0d 1a fc}  //weight: 2, accuracy: High
        $x_2_2 = {c8 a4 57 ba 32 c3 69 e8 93 81 e1 87 67 21 e6 4e e4 a1 d4 d7 da c9 ff a5 bd 17 b7 48 47 9a 05 59 63 20 ff 51 3c 53 be}  //weight: 2, accuracy: High
        $x_1_3 = "Click to break in debugger!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Wabot_SCP_2147944466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wabot.SCP!MTB"
        threat_id = "2147944466"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {2e 72 73 72 63 00 00 00 58 15 00 00 00 90 01 00 00 16 00 00 00 a0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 50 00 00 00 00 00 00 00 00 00 e0 78 00 00 b0 01 00 00 28 03 00 00 b6 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 64 61 74 61}  //weight: 3, accuracy: High
        $x_2_2 = {67 56 61 49 6c b2 bb 4e 1a 93 7a 65 bc 9c f4 f5 58 93 78 f5 ce 83 89 7d 32 62 d3 c3 ec 2c b1 b9 69 d2 4c 73 79 bc bb 61 2b 8b eb 1e 0c c9 ae 29 99 c1 3c 76 0e 8c 79 6f 52 62 e1 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

