rule Trojan_Win32_Sdum_EM_2147847282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sdum.EM!MTB"
        threat_id = "2147847282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sdum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ipconfig /release & ipconfig /flushdns & ipconfig /renew" ascii //weight: 1
        $x_1_2 = "shutdown /s /t 29 /c" ascii //weight: 1
        $x_1_3 = "rundll32 user32.dll,LockWorkStation" ascii //weight: 1
        $x_1_4 = "InternetConnectA" ascii //weight: 1
        $x_1_5 = "taskkill /f /im" ascii //weight: 1
        $x_1_6 = "3fbd04f5-b1ed-4060-99b9-fca7ff59c113" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sdum_GMC_2147853356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sdum.GMC!MTB"
        threat_id = "2147853356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sdum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 07 8b d1 83 e2 03 8a 54 3a 0c 03 c1 30 10 41 3b 4f 04 72 eb}  //weight: 10, accuracy: High
        $x_10_2 = {0f b6 4d dd 0f b6 47 0d 0f b6 55 dc 33 c1 0f b6 4f 0c c1 e0 08 33 ca}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sdum_RE_2147888277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sdum.RE!MTB"
        threat_id = "2147888277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sdum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Inverse Server Sinergic\\Inverse 8.2\\Server\\Inv ReWork" wide //weight: 1
        $x_1_2 = "1230\\svshost.exe" wide //weight: 1
        $x_1_3 = "sc.exe config wscsvc start" wide //weight: 1
        $x_1_4 = "1230\\smss.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sdum_DS_2147888638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sdum.DS!MTB"
        threat_id = "2147888638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sdum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 7f ec 36 d8 89 dc b2 bf 59 8c 50 f1 03 85 01 c4 43 2e a4 7c 6b 07 af 67 18 ba d6 e0 ef d1 d7 01 84 83 a2 5d 2a 11 38 65 a4 fb 5b 30 42 84 c2 0f 3d 28 f7 fd fa 4e 4b e6 65 0a c9 95 dd de f0}  //weight: 1, accuracy: High
        $x_1_2 = {0e d3 21 71 a0 10 ea 03 c2 72 ca 3e 02 00 c2 43 63 01 29 50 3a db 89 e3 58 36 80 c1 ed 6d d1 2b 1e 45 9b 21 6a da 51 19 d6 3d 1c 0b 17 44 cb 49 14 3d b3 40 86 f0 f6 e7 29 ea 48 79 5c ba a6 d9 b0 50 3d f7 e9 11 78 c6 71}  //weight: 1, accuracy: High
        $x_1_3 = {55 7e 80 52 48 ce 82 5b ce e4 39 3e 55 88 d3 ca 81 7f ec 36 d8 89 dc b2 bf 59 8c 50 f1 03 85 01 c4 43 2e a4 7c 6b 07 af 67 18 ba d6 e0 ef d1 d7 01 84 83 a2 5d 2a 11 38 65 a4 fb 5b 30 42 84 c2}  //weight: 1, accuracy: High
        $x_1_4 = {20 41 22 51 5e b1 47 eb b9 dd 38 4c 21 30 cb 2a f3 55 4c 6d 46 ba 82 09 d9 44 c0 33 15 58 be 56 d3 94 79 69 d1 de 58 c8 2a 57 78 46 0d 6d 21 b4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sdum_GMD_2147897363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sdum.GMD!MTB"
        threat_id = "2147897363"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sdum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 07 8b d1 83 e2 03 8a 54 3a 0c 03 c1 30 10 41 3b 4f 04}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sdum_GPA_2147902712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sdum.GPA!MTB"
        threat_id = "2147902712"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sdum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b c1 5e f7 f6 8b 45 08 8a 04 02 30 04 19 41 3b cf 72 e9}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

