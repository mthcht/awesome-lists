rule TrojanSpy_Win32_Ploscato_D_2147680395_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ploscato.D"
        threat_id = "2147680395"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ploscato"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 73 65 72 33 37 37 30 34 00}  //weight: 1, accuracy: High
        $x_1_2 = {64 75 6d 2e 65 78 65 00 6f 75 74 70 75 74 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 73 69 6c 65 6e 74 69 6e 73 74 61 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = "videodrv" ascii //weight: 1
        $x_1_5 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 72 65 67 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = "dump grabber" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_Ploscato_A_2147685065_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ploscato.A"
        threat_id = "2147685065"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ploscato"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 5b 00 00 00 b8 cc cc cc cc f3 ab b9 09 00 00 00 be ?? ?? ?? ?? 8d 7d d4 f3 a5 a4 8a 45 e0 88 85 7c ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = "z:\\Projects\\Rescator\\uploader\\Debug\\scheck.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ploscato_B_2147685087_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ploscato.B"
        threat_id = "2147685087"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ploscato"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d bd 40 ff ff ff b9 30 00 00 00 b8 cc cc cc cc f3 ab 83 7d 08 02 75 0c}  //weight: 1, accuracy: High
        $x_1_2 = "\\Rescator\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ploscato_C_2147689094_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ploscato.C"
        threat_id = "2147689094"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ploscato"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 80 34 08 4d 41 83 f9 46 7c f3}  //weight: 1, accuracy: High
        $x_1_2 = {83 f2 21 89 95 ec ff fd ff 83 fa 1c 74 17 83 fa 65 74 12 83 fa 7f 74 0d b2 01 d2 e2 f6 d2 20 10}  //weight: 1, accuracy: High
        $x_1_3 = {72 bf 33 ff 0f b6 05 ?? ?? ?? ?? 50 0f b6 87 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 32 05 ?? ?? ?? ?? 47 88 87 ?? ?? ?? ?? 59 59 81 ff 0c 01 00 00 72 d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanSpy_Win32_Ploscato_E_2147690069_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ploscato.E"
        threat_id = "2147690069"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ploscato"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 6d 65 6d 64 75 6d 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {4b 41 50 54 4f 58 41 00}  //weight: 1, accuracy: High
        $x_1_3 = {47 4f 54 49 54 20 00}  //weight: 1, accuracy: High
        $x_1_4 = {50 4f 53 57 44 53 00}  //weight: 1, accuracy: High
        $x_1_5 = {4d 6d 6f 6e 4e 65 77 5c 44 65 62 75 67 5c 6d 6d 6f 6e 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_6 = {73 4e 62 72 6c 53 66 79 42 4d 32 50 52 35 37 54 71 33 51 65 56 70 6e 57 34 2b 77 38 4a 4f 48 4b 36 43 6f 67 75 59 78 76 6b 2f 49 64 5a 30 4c 58 6a 55 61 41 68 47 7a 44 46 6d 63 74 39 45 69 31 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_Win32_Ploscato_F_2147690070_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ploscato.F"
        threat_id = "2147690070"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ploscato"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2d 73 65 74 64 00}  //weight: 1, accuracy: High
        $x_1_2 = "Usage: -[start|stop|install|uninstall]" ascii //weight: 1
        $x_1_3 = {61 6c 65 72 74 2e 25 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {62 65 61 63 6f 6e 2e 25 73 2e 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

