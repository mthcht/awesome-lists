rule Trojan_Win32_Chksyn_A_2147598095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chksyn.gen!A"
        threat_id = "2147598095"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chksyn"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 e8 00 00 00 00 83 7d e4 00 75 0a b8 0f 00 00 c0 e9 91 00 00 00 83 7d ec 00 75 10 8b 55 e4 83 c2 64}  //weight: 1, accuracy: High
        $x_1_2 = {50 8b 4d f0 83 c1 04 51 e8 ?? 23 00 00 83 c4 08 85 c0 74 07 c7 45 f4 34 00 00 c0 68 ?? ?? ?? ?? 6a 00}  //weight: 1, accuracy: Low
        $x_1_3 = {74 4e 68 00 01 00 00 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? b8 ?? ?? ?? ?? 99 52 50 68 76 01 00 00 e8 ?? ?? ff ff 85 c0 74 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Chksyn_A_2147598095_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chksyn.gen!A"
        threat_id = "2147598095"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chksyn"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 0a 30 0c 06}  //weight: 1, accuracy: High
        $x_1_2 = {8b 40 0c 8b 40 1c 8b 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 70 1c ad 8b 40 08 (5e|e9)}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 34 9a 5a 5b}  //weight: 1, accuracy: High
        $x_1_5 = {8b 04 9a 5a 5b}  //weight: 1, accuracy: High
        $x_1_6 = {8b 40 30 83 b8 b0 00 00 00 02 0f (84|85)}  //weight: 1, accuracy: Low
        $x_1_7 = {33 d2 64 89 25 00 00 00 00 ff 12}  //weight: 1, accuracy: High
        $x_1_8 = {68 3f 26 cb 10 e8}  //weight: 1, accuracy: High
        $x_1_9 = {68 b9 2c ff e6 89 7d f8}  //weight: 1, accuracy: High
        $x_1_10 = {68 44 a6 ca 0b e8}  //weight: 1, accuracy: High
        $x_1_11 = {68 83 8e f1 66 e8}  //weight: 1, accuracy: High
        $x_1_12 = {68 7e 18 ba ce e8}  //weight: 1, accuracy: High
        $x_1_13 = {c6 00 8b e8}  //weight: 1, accuracy: High
        $x_2_14 = {68 b5 7e 38 c6 89 45}  //weight: 2, accuracy: High
        $x_2_15 = {68 f8 32 31 c6 e8}  //weight: 2, accuracy: High
        $x_2_16 = {c6 00 c3 ff 14 24}  //weight: 2, accuracy: High
        $x_2_17 = {8b 45 08 c6 00 b8}  //weight: 2, accuracy: High
        $x_2_18 = {89 48 01 66 c7 40 05 ff e0}  //weight: 2, accuracy: High
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

rule Trojan_Win32_Chksyn_D_2147629073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chksyn.D"
        threat_id = "2147629073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chksyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 3c ba 6c 00 00 00 8b 85 ?? ?? ?? ?? 66 89 50 04 b9 6f 00 00 00 8b 95 ?? ?? ?? ?? 66 89 4a 08 b8 73 00 00 00 8b 8d ?? ?? ?? ?? 66 89 41 0c ba 74 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 11 88 10 8b 45 08 83 c0 01 89 45 08 8b 4d 0c 83 c1 01 89 4d 0c 8b 55 10 83 ea 01 89 55 10 75 d9}  //weight: 1, accuracy: High
        $x_1_3 = {0f be 48 ff 83 f9 3a 75 27 8d 55 f4 52 8b 45 fc 83 c0 01 50 e8 ?? ?? ?? ?? 85 c0 75 13}  //weight: 1, accuracy: Low
        $x_1_4 = "un=%s&v=%d&s=%d&h=%d&o=%d&w=%d&c=%d&ip=%s&sys=%s&uid=%d&ftp=%s" ascii //weight: 1
        $x_1_5 = "m=%s&p=%s&v=%d&b=%s&u=%d&s=%s&headers=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Chksyn_E_2147637649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chksyn.E"
        threat_id = "2147637649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chksyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "v=%d&s=%d&h=%d&un=%s&ftp=%s&o=%d&c=%d&ip=%s&sys=%s&uid=%d&w=%d" ascii //weight: 1
        $x_1_2 = ".exe firewall add allowedprogram program = " ascii //weight: 1
        $x_1_3 = "LoadAppInit_DLLs" wide //weight: 1
        $x_1_4 = "Macromedia\\SwUpdate\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chksyn_F_2147649371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chksyn.F"
        threat_id = "2147649371"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chksyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c9 35 4e 5a 01 83 c1 01 89 0d ?? ?? ?? 00 8b 15 ?? ?? ?? 00 c1 ea 10 0f b7 c2 25 ff ff 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Microsoft Windows Explorer\" mode = ENABLE" ascii //weight: 1
        $x_1_3 = "Service\" mode = ENABLE" ascii //weight: 1
        $x_1_4 = {6a f1 6a fe ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_5 = {c6 45 ec e9 8b 45 0c 2b 45 08 83 e8 05 89 45 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chksyn_G_2147717725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chksyn.G"
        threat_id = "2147717725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chksyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 01 33 d2 32 44 15 ?? 42 83 fa 0d 72 f6 88 01 41 4e 75 ec}  //weight: 1, accuracy: Low
        $x_1_2 = {80 bd 8c fd ff ff 55 0f 85 ?? ?? ?? ?? 80 bd 8d fd ff ff 3a}  //weight: 1, accuracy: Low
        $x_1_3 = {6e 65 74 20 73 74 6f 70 20 57 69 6e 44 65 66 65 6e 64 [0-8] 6e 65 74 20 73 74 6f 70 20 4d 70 73 53 76 63}  //weight: 1, accuracy: Low
        $x_1_4 = "v=%d&s=%d&h=%d&un=%s&o=%d&c=%d&ip=%s&sys=%s&uid=%d&w=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

