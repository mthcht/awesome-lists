rule Trojan_Win32_Lotok_DSK_2147753270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lotok.DSK!MTB"
        threat_id = "2147753270"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4d 08 40 33 ff 89 45 e8 57 8a 04 10 8a 14 0e 32 d0 88 14 0e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lotok_CC_2147811078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lotok.CC!MTB"
        threat_id = "2147811078"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 83 fe 01 75 02 33 f6 8a 14 39 0f b7 c6 80 ea 7a 8a 44 45 12 32 c2 46 88 04 39 41 3b 4d 0c 7c df}  //weight: 1, accuracy: High
        $x_1_2 = {33 f6 8b 45 08 8d 0c 02 0f b7 c6 8a 44 45 ec 30 01 46 42 3b d7 72 e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lotok_AH_2147816413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lotok.AH!MTB"
        threat_id = "2147816413"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 e8 8a 10 8a 4d ef 32 d1 02 d1 88 10}  //weight: 2, accuracy: High
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lotok_CB_2147817062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lotok.CB!MTB"
        threat_id = "2147817062"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 08 02 ca 32 ca 02 ca 32 ca 88 08 40 4e 75 da}  //weight: 2, accuracy: High
        $x_2_2 = "VirtualAlloc" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lotok_CD_2147817579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lotok.CD!MTB"
        threat_id = "2147817579"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 f0 4b c6 45 f1 45 c6 45 f2 52 c6 45 f3 4e c6 45 f4 45 c6 45 f5 4c c6 45 f6 33 c6 45 f7 32 c6 45 f8 2e c6 45 f9 64 c6 45 fa 6c c6 45 fb 6c c6 45 fc 00 c6 45 e0 56 c6 45 e1 69 c6 45 e2 72 c6 45 e3 74 c6 45 e4 75 c6 45 e5 61 c6 45 e6 6c c6 45 e7 41 c6 45 e8 6c c6 45 e9 6c c6 45 ea 6f c6 45 eb 63 c6 45 ec 00 8d 45 e0 50}  //weight: 1, accuracy: High
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lotok_RC_2147846520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lotok.RC!MTB"
        threat_id = "2147846520"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 44 24 2c 2a c3 03 d1 8b 0d ?? ?? ?? ?? 32 c3 89 15 ?? ?? ?? ?? 8b 54 24 1c 2b cd 02 c3 89 0d ?? ?? ?? ?? 88 04 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lotok_DAP_2147850624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lotok.DAP!MTB"
        threat_id = "2147850624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2a cb 23 c2 32 cb 89 15 ?? ?? 40 00 8b 54 24 14 a3 ?? ?? 40 00 8b 44 24 10 02 cb 88 0c 10 40 84 c9 89 44 24 10 74}  //weight: 2, accuracy: Low
        $x_2_2 = "4f5e596d885941898859844d0c0cfea5d207edaf6aac09f795af21893786d620a12a228f4f15813e68af19701a3c89961770" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lotok_RPY_2147851474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lotok.RPY!MTB"
        threat_id = "2147851474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 8b f0 66 c7 44 24 14 02 00 ff 15 ?? ?? ?? ?? 66 89 44 24 12 8b 46 0c 6a 10 8b 08 8d 44 24 14 50 8b 11 8b 4b 08 51 89 54 24 20 ff 15 ?? ?? ?? ?? 83 f8 ff 75 1b 8b 53 0c 52 ff 15 ?? ?? ?? ?? 8b 43 0c 68 e8 03 00 00 50 ff 15 ?? ?? ?? ?? eb a8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lotok_CBU_2147851509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lotok.CBU!MTB"
        threat_id = "2147851509"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 56 6a 40 68 00 30 00 00 68 5c dc 04 00 6a 00 8b f1 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lotok_CBV_2147851558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lotok.CBV!MTB"
        threat_id = "2147851558"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 68 5c dd 04 00 8b f1 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lotok_A_2147851559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lotok.A!MTB"
        threat_id = "2147851559"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 8b f8 66 c7 44 24 14 02 00 ff 15 ?? ?? ?? ?? 66 89 44 24 12 8b 47 0c 6a 10 8b 08 8d 44 24 14 50 8b 11 8b 4e 08 51 89 54 24 20 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lotok_CH_2147851796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lotok.CH!MTB"
        threat_id = "2147851796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {83 ec 64 56 57 8b f9 50 68 ?? ?? 40 00 8d 4c 24 10 68 ?? ?? 40 00 51 ff 15 ?? ?? 40 00 83 c4 10 8d 54 24 08 52 6a 00 6a 00 ff 15}  //weight: 4, accuracy: Low
        $x_1_2 = {6a 40 68 00 30 00 00 68 5c dc 04 00 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lotok_CI_2147895070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lotok.CI!MTB"
        threat_id = "2147895070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\ProgramData" ascii //weight: 1
        $x_1_2 = "4f5e596d885941898859844d0c0cfea5d207edaf6aac09f795af21893786d620a12a228f4f15813e68af19701a3c89961770" ascii //weight: 1
        $x_1_3 = "3b39683f393e6a393e1e221c0c0876804985c38c1ede81e8d7005155a6399c8e881d1ca8010186cb424f7eeda9a04f5500a0" ascii //weight: 1
        $x_1_4 = "5e596f8a0c3c1e7878e485273dc52f5ec4572593743f310472a87ca59e0e88958127b65b2e53cea7f130b95e188bf208b4ef" ascii //weight: 1
        $x_1_5 = "6a555e88896d604d6060636f0c8e75f5a4153c6e032ea6f28825a44d42692f77ad588b2288e39b08251977001a2aabc31c5d" ascii //weight: 1
        $x_1_6 = "5f5962580c585979017935195aa97d75fa9cc89e2914fd4e192e6fccc8328cdbb2c8df54a6261e6746c361ebde1037f01ebf" ascii //weight: 1
        $x_1_7 = "6b3f4d3f886d5e88895c0c6dd0de7d6360adf0398c569e0169f1245020276db124cf37b423ce35f9625da7738ca8041072d2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lotok_EM_2147895407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lotok.EM!MTB"
        threat_id = "2147895407"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "runas" ascii //weight: 1
        $x_1_2 = "\\edge.jpg" ascii //weight: 1
        $x_1_3 = "\\edge.xml" ascii //weight: 1
        $x_1_4 = "http://%s/%d" ascii //weight: 1
        $x_1_5 = "613880B3-8AF3-4350-BF41-83FB6619F485" ascii //weight: 1
        $x_1_6 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_7 = "ShellExecuteExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lotok_RG_2147895466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lotok.RG!MTB"
        threat_id = "2147895466"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 4c 1f 01 32 0c 1f 89 da d1 ea 83 c3 02 88 0c 17 81 fb ?? ?? ?? ?? 72 e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lotok_GPA_2147898302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lotok.GPA!MTB"
        threat_id = "2147898302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {45 b1 52 68 08 b5 09 00 c6 44 24 10 47 88 44 24 11 c6 44 24 12 54 c6 44 24 13 53 88 44 24 14 88 4c 24 15 c6 44 24 16 56 88 44 24 17 88 4c 24 18 c6 44 24 19 32 c6 44 24 1a 2e c6 44 24 1b 30}  //weight: 2, accuracy: High
        $x_2_2 = "yinggshishiz" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lotok_GPB_2147902461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lotok.GPB!MTB"
        threat_id = "2147902461"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {51 59 66 49 52 5a 32 06 9c 50 b8}  //weight: 4, accuracy: High
        $x_4_2 = {88 07 60 66 89 c8 66 89 c7 61 46 60 89 f3 89 da 61 47 9c 66 56}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lotok_NK_2147903217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lotok.NK!MTB"
        threat_id = "2147903217"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "38.181.22.54" ascii //weight: 2
        $x_2_2 = "Bsjbs.exe" ascii //weight: 2
        $x_1_3 = "Fwnfwnfv Ogwofwofw Ogxogwo Hxpgxpgx Phy" ascii //weight: 1
        $x_1_4 = "Aqiyqi Ariariaq Jbrjarja Sjbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lotok_RK_2147906604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lotok.RK!MTB"
        threat_id = "2147906604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 04 02 99 f7 ff 8b c6 80 c2 ?? 30 11 59 99 f7 f9 ff 45 ?? 85 d2 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lotok_RL_2147906605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lotok.RL!MTB"
        threat_id = "2147906605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 14 99 59 f7 f9 6a 00 89 45 e8 8b 46 58 99 f7 f9 89 45 ec ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

