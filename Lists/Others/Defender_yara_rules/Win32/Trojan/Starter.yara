rule Trojan_Win32_Starter_H_2147642790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Starter.H"
        threat_id = "2147642790"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Starter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "e:\\free\\web1.0\\Svchost\\Release\\SVCHOST.pdb" ascii //weight: 3
        $x_2_2 = "\\dodolook.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Starter_L_2147651638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Starter.L"
        threat_id = "2147651638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Starter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\MSoftware" ascii //weight: 1
        $x_1_2 = "killall**" ascii //weight: 1
        $x_2_3 = "ade34ea82c4f7f2f.net" ascii //weight: 2
        $x_2_4 = "f19dd4abb8b8bdf2.cn" ascii //weight: 2
        $x_2_5 = "79ecbf1c3a6c76b8.net" ascii //weight: 2
        $x_1_6 = "data.cgi" ascii //weight: 1
        $x_1_7 = "get.cgi?" ascii //weight: 1
        $x_1_8 = "msftldr.dll" ascii //weight: 1
        $x_1_9 = "msfttmp.dll" ascii //weight: 1
        $x_1_10 = "msfttmpcfg" ascii //weight: 1
        $x_1_11 = "msftcore.dat" ascii //weight: 1
        $x_2_12 = {1e 21 89 10 ad 10 e2 80 3c 00 46 da ad 20 e2 1b 2c 92 ca}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Starter_P_2147695002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Starter.P"
        threat_id = "2147695002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Starter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 39 52 65 67 4f 75 ?? 8d 41 04 81 38 70 65 6e 4b}  //weight: 1, accuracy: Low
        $x_1_2 = {81 39 45 78 69 74 75 ?? 8d 41 04 81 38 50 72 6f 63}  //weight: 1, accuracy: Low
        $x_1_3 = {66 c7 85 00 fd ff ff 73 00 66 c7 85 02 fd ff ff 68 00 66 c7 85 04 fd ff ff 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {32 84 95 00 [0-1] ff ff 8b 95 4c ff ff ff 88 04 32 46 ff 8d 3c ff ff ff 75}  //weight: 1, accuracy: Low
        $x_1_5 = {c6 85 2f ff ff ff 61 c6 85 30 ff ff ff 64 c6 85 31 ff ff ff 76}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Starter_P_2147695002_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Starter.P"
        threat_id = "2147695002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Starter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 39 52 65 67 4f 75 ?? 8d 41 04 81 38 70 65 6e 4b}  //weight: 1, accuracy: Low
        $x_1_2 = {81 39 45 78 69 74 75 ?? 8d 41 04 81 38 50 72 6f 63}  //weight: 1, accuracy: Low
        $x_1_3 = {66 c7 85 00 fd ff ff 73 00 66 c7 85 02 fd ff ff 68 00 66 c7 85 04 fd ff ff 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {32 84 95 00 [0-1] ff ff 8b 95 4c ff ff ff 88 04 32 46 ff 8d 3c ff ff ff 75}  //weight: 1, accuracy: Low
        $x_1_5 = {c6 85 2f ff ff ff 61 c6 85 30 ff ff ff 64 c6 85 31 ff ff ff 76}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Starter_R_2147726795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Starter.R"
        threat_id = "2147726795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Starter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\x.bat\" & echo bitsadmin /complete " wide //weight: 1
        $x_1_2 = "\\x.bat\" & echo bitsadmin /cancel " wide //weight: 1
        $x_1_3 = "\\x.bat\" & echo start /b /min regsvr32.exe /s /n /i:\"!=" wide //weight: 1
        $x_1_4 = "for /f %i in ('dir /a:-d /b /w " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Starter_ARA_2147890086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Starter.ARA!MTB"
        threat_id = "2147890086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Starter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "rasphone.pdb" ascii //weight: 2
        $x_2_2 = "crashreporter.pdb" ascii //weight: 2
        $x_2_3 = "SubmitCrashReport" ascii //weight: 2
        $x_2_4 = "\\*.dmp" ascii //weight: 2
        $x_2_5 = "Software\\Classes\\Applications\\crashreporter.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Starter_CCJK_2147921777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Starter.CCJK!MTB"
        threat_id = "2147921777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Starter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 dc 89 44 24 04 8b 45 e0 89 04 24 e8 dc 94 01}  //weight: 5, accuracy: High
        $x_6_2 = {c7 44 24 14 01 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 89 44 24 08 c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00 e8 cc 91 01}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

