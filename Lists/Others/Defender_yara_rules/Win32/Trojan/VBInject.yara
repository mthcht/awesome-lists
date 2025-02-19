rule Trojan_Win32_VBInject_K_2147642470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.K"
        threat_id = "2147642470"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sEspacioPoison" ascii //weight: 1
        $x_1_2 = "ShellExecuteA" ascii //weight: 1
        $x_1_3 = "ModMePublico\\Stu#b\\Proyecto1.vbp" wide //weight: 1
        $x_1_4 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 4c 00 6f 00 61 00 64 00 65 00 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_N_2147644293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.N"
        threat_id = "2147644293"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {81 bd bc fe ff ff 50 45 00 00 0f 85 ?? ?? ?? ?? 8b 0e 8b c3 8d 95 bc fe ff ff 83 c0 34 52 6a 04 0f 80 ?? ?? ?? ?? 50 56 ff 51 24 8b 8d bc fe ff ff 8b 55 c4 89 4d d4 8d 8d 68 ff ff ff c7 02 44 00 00 00 ba ?? ?? ?? ?? ff 15}  //weight: 5, accuracy: Low
        $x_1_2 = "\\CASH\\CASH" wide //weight: 1
        $x_1_3 = {68 95 1f 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "/C start explorer.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VBInject_P_2147645585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.P"
        threat_id = "2147645585"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:\\Users\\P\\Desktop\\P0is0n\\Programacion\\RedEdition\\Black\\" wide //weight: 2
        $x_1_2 = {70 50 72 6f 79 00 50 72 6f 6a 65 63 74 31 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_S_2147656154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.S"
        threat_id = "2147656154"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 52 6a 01 6a ff 6a 20 ff 15 ?? 11 40 00 c7 45 fc ?? 00 00 00 0c 00 c7 45 fc ?? 00 00 00 8b 15 3c ?? (41|42)}  //weight: 1, accuracy: Low
        $x_1_2 = {73 0c c7 85 ?? ff ff ff 00 00 00 00 eb 0c ff 15 ?? (10|11) 40 00 89 85 ?? ff ff ff 8b 45 ?? 8b 0d 20 ?? 41 00 8b 14 81 52 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {fd ff ff 02 00 01 00 c7 45 fc ?? 00 00 00 8d 03 00 c7 85}  //weight: 1, accuracy: Low
        $x_5_4 = {81 e1 ff 00 00 00 ff 15 ?? 11 40 00 8b 55 (b4|b8|bc) 8b 4a 0c 8b ?? ?? fe ff ff 88 04 11 c7 45 fc ?? 00 00 00 e9 ?? f6 ff ff c7 45 fc ?? 00 00 00}  //weight: 5, accuracy: Low
        $x_1_5 = {c7 45 fc 03 00 00 00 c7 45 ?? 00 00 00 00 c7 45 ?? 02 00 00 00 8d 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c4 0c c7 45 fc 04 00 00 00 68 ff 00 00 00 8b 55 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? c7 45 fc 05 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VBInject_T_2147661149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.T"
        threat_id = "2147661149"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 40 00 00 e8 ?? ?? f8 ff 66 3d ff ff 74 05 e8 ?? ff ff ff 56 56}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_DS_2147740553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.DS!MTB"
        threat_id = "2147740553"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 34 08 5b 66 0f 6e d3 [0-32] e8 [0-4] f6 [0-32] 66 0f 7e 14 08 [0-16] 83 e9 fc 81 f9 ?? ?? ?? ?? 75 ?? f6 [0-16] c3 f6 [0-16] 66 0f ef d1 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_BS_2147743794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.BS!MTB"
        threat_id = "2147743794"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 8b 16 33 c9 8b 42 0c 8b 95 48 ff ff ff 8a 0c 10 8b 45 d8 25 ff 00 00 00 8b d7 33 c8 81 e2 ff 00 00 00 33 ca ff 15 ?? ?? ?? ?? 8b 0e 8b 51 0c 88 04 1a 8b 45 dc 8b 5d e0 03 c7 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_BS_2147743794_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.BS!MTB"
        threat_id = "2147743794"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 dc 01 00 00 00 c7 45 e0 01 00 00 00 83 65 e8 00 eb ?? 8b 45 e8 03 45 e0 89 45 e8 8b 45 e8 3b 45 dc 7f ?? eb ?? e8 ?? ?? ?? ?? 32 32 8b 45 08 8b 00 ff 75 08 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 ee ff ff 00 d9 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_BS_2147743794_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.BS!MTB"
        threat_id = "2147743794"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 08 8b 55 dc 2b 51 14 89 55 cc 8b 45 08 8b 08 8b 55 cc 3b 51 10 73}  //weight: 1, accuracy: High
        $x_1_2 = {eb 0c ff 15 ?? ?? ?? ?? 89 85 60 ff ff ff 8b 4d d8 ff 15 ?? ?? ?? ?? 8b 4d 08 8b 11 8b 4a 0c 8b 95 60 ff ff ff 88 04 11 c7 45 fc 25 00 00 00 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_BS_2147743794_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.BS!MTB"
        threat_id = "2147743794"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 00 02 80 c7 85 ?? ?? ?? ?? 0a 00 00 00 c7 85 ?? ?? ?? ?? 04 00 02 80 c7 85 ?? ?? ?? ?? 0a 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "qCHrs7H8t0xv7a1i6eTLRORWh0dlQarT30" wide //weight: 1
        $x_1_3 = "Hb0pqVlYhZtNrUDJzOjVHGf81" wide //weight: 1
        $x_1_4 = "uYkImp0VgsVowU97gc1xeSraUnFyL64" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_BA_2147744752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.BA!MTB"
        threat_id = "2147744752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 f9 1f 8b d1 33 c8 33 d7 3b ca 7f 1f 8b 4d 0c 8b 09 8b 51 0c 8b 79 14 2b d7 8a cb 8d 3c 02 8a 14 02 33 ca 33 c8 03 c6 88 0f eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_CB_2147745856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.CB!MTB"
        threat_id = "2147745856"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 8b cf 66 83 c1 06 66 0f b6 04 02 66 99 0f 80 ?? ?? ?? ?? 66 f7 f9 66 8b ca 8b 13 8b 42 0c 8b 95 ?? ?? ?? ?? 66 0f b6 04 10 33 c8 ff 15 ?? ?? ?? ?? 8b 0b 8b 51 0c 88 04 32 b8 01 00 00 00 66 03 c7 bf 02 00 00 00 0f 80}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_CB_2147745856_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.CB!MTB"
        threat_id = "2147745856"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 33 c0 8a c1 8b 4d ?? 66 89 04 79 8b 45 ?? 8b 00 8b 58 ?? 8b 48 ?? 2b cb 8d 04 11 8b 4d ?? 66 8b 1c 79 66 03 1c 71 66 83 e3 0f 79 ?? 66 4b 66 83 cb f0 66 43 0f bf db 8a 0c 59 30 08 03 95 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_CD_2147747970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.CD!MTB"
        threat_id = "2147747970"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b cb 8d 04 11 8b 4d b8 66 8b 1c 79 66 03 1c 71 66 83 e3 0f 79 ?? 66 4b 66 83 cb f0 66 43 0f bf db 8a 0c 59 8a 18 32 d9 88 18 8b 85 6c ff ff ff 03 d0 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_CZ_2147748503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.CZ!MTB"
        threat_id = "2147748503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b f2 3b f1 72 ?? ff ?? eb ?? ff ?? 8b f0 8b 45 08 8b 08 8b 85 10 ff ff ff 8b 51 0c 66 0f b6 0c 02 8b 55 b4 66 33 0c 7a ff 15 ?? ?? ?? ?? 8b 4d 08 8b 11 8b 4a 0c 88 04 31 8b 4d cc b8 01 00 00 00 03 c1 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_CF_2147749294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.CF!MTB"
        threat_id = "2147749294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d79zHkQJJZRWxuQSp1Zo7oHZt194" wide //weight: 1
        $x_1_2 = "s2Koyx3c639enoUQ40jflWs6657guwd192" wide //weight: 1
        $x_1_3 = "kiHQMtRvCI0CQFzYQGK5Xl196" wide //weight: 1
        $x_1_4 = "vNFXTl9p6kEQaaalI141" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_HA_2147749825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.HA!MTB"
        threat_id = "2147749825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "o6njn5Vnj4LMGx0rLmx2znrGQ8FMsR3aVNtw215" wide //weight: 1
        $x_1_2 = "JkzofSVItYygILUiCmq1N165" wide //weight: 1
        $x_1_3 = "zNAOzpfzhuwpWeqGyq5cJZkROKh89" wide //weight: 1
        $x_1_4 = "RFkAQSzy9DrIw6z173" wide //weight: 1
        $x_1_5 = "Ad34jUFpZ09QhDWFzJ145" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_AM_2147755539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.AM!MSR"
        threat_id = "2147755539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chadarim8" ascii //weight: 1
        $x_1_2 = "Individuals2" ascii //weight: 1
        $x_1_3 = "Capitalization" ascii //weight: 1
        $x_1_4 = "Ambitioned0" ascii //weight: 1
        $x_1_5 = "barbels" ascii //weight: 1
        $x_1_6 = "Ateliers8" ascii //weight: 1
        $x_1_7 = "Awninged3" ascii //weight: 1
        $x_1_8 = "Bundlers3" ascii //weight: 1
        $x_1_9 = "Aiding" ascii //weight: 1
        $x_1_10 = "Headstrong" ascii //weight: 1
        $x_1_11 = "Assays6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_VA_2147755778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.VA!MSR"
        threat_id = "2147755778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfvxvxvvxcvvv" ascii //weight: 1
        $x_1_2 = "qqqqqqqqqqqqaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ascii //weight: 1
        $x_1_3 = "rfffffffffffffffffffffffffffffffffffffswrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr" ascii //weight: 1
        $x_1_4 = "fsdffffffrterwrerw" ascii //weight: 1
        $x_1_5 = "frmLogin" ascii //weight: 1
        $x_1_6 = "frmSplash" ascii //weight: 1
        $x_1_7 = "frmTip" ascii //weight: 1
        $x_1_8 = "frmBrowser" ascii //weight: 1
        $x_1_9 = "frmOptions" ascii //weight: 1
        $x_1_10 = "frmODBCLogon" ascii //weight: 1
        $x_1_11 = "frmOptions1" ascii //weight: 1
        $x_1_12 = "frmLogin1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_AA_2147756457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.AA!MTB"
        threat_id = "2147756457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0f eb 01 ?? eb 01 ?? 6a 00 eb 01 ?? eb 01 ?? 89 0c 24 eb 01 ?? eb 01 ?? 31 34 24 eb 01 ?? eb 01 ?? 59 eb 01 ?? eb 01 ?? e8 35 00 00 00 eb 01}  //weight: 1, accuracy: Low
        $x_1_2 = {8f 04 18 eb 01 ?? eb 01 ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_AV_2147757230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.AV!MSR"
        threat_id = "2147757230"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Creators6" ascii //weight: 1
        $x_1_2 = "Atopic" ascii //weight: 1
        $x_1_3 = "clustering" ascii //weight: 1
        $x_1_4 = "apiary" ascii //weight: 1
        $x_1_5 = "expounded" ascii //weight: 1
        $x_1_6 = "Civilizable" ascii //weight: 1
        $x_1_7 = "amicabilities" ascii //weight: 1
        $x_1_8 = "computerizes" ascii //weight: 1
        $x_1_9 = "scassi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_AVI_2147758178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.AVI!MSR"
        threat_id = "2147758178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Clitoridean4" ascii //weight: 1
        $x_1_2 = "Adsorbed" ascii //weight: 1
        $x_1_3 = "alphabetization" ascii //weight: 1
        $x_1_4 = "Desolateness" ascii //weight: 1
        $x_1_5 = "Apocryphalness" ascii //weight: 1
        $x_1_6 = "pawer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_AVP_2147759090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.AVP!MSR"
        threat_id = "2147759090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "chickasaws" ascii //weight: 1
        $x_1_2 = "cakier" ascii //weight: 1
        $x_1_3 = "abominates" ascii //weight: 1
        $x_1_4 = "Broke" ascii //weight: 1
        $x_1_5 = "Lemur" ascii //weight: 1
        $x_1_6 = "Belows" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_MR_2147776805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.MR!MTB"
        threat_id = "2147776805"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 d1 83 f8 [0-8] 81 [0-5] 01 ?? 83 [0-2] 3d [0-4] 8b ?? 3d [0-4] 83 [0-2] 81 [0-5] 81 [0-5] 3d [0-4] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_VA_2147782405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.VA!MTB"
        threat_id = "2147782405"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Demarkationslinjens7" ascii //weight: 3
        $x_3_2 = "nervemedicins" ascii //weight: 3
        $x_3_3 = "knopskyde" ascii //weight: 3
        $x_3_4 = "stningsstrukturer" ascii //weight: 3
        $x_3_5 = "EmptyClipboard" ascii //weight: 3
        $x_3_6 = "HideCaret" ascii //weight: 3
        $x_3_7 = "GetFileInformationByHandle" ascii //weight: 3
        $x_3_8 = "WNetGetUserA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_PO_2147788124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.PO!MTB"
        threat_id = "2147788124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Huawei" wide //weight: 1
        $x_1_2 = "AVG Technologies" wide //weight: 1
        $x_1_3 = "CamStudio Group" wide //weight: 1
        $x_1_4 = "Sourcefire, Inc." wide //weight: 1
        $x_1_5 = "Worldcoin" wide //weight: 1
        $x_1_6 = "FileZilla Project" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_EA_2147788926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.EA!MTB"
        threat_id = "2147788926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 f0 83 c6 01 31 f0 3b 84 24 18 01 00 00 75 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_E_2147813754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.E!MTB"
        threat_id = "2147813754"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "cliente nuevo\\stub\\stub.vbp" ascii //weight: 3
        $x_3_2 = "vaquitamala" ascii //weight: 3
        $x_3_3 = "JPEGsnoop" ascii //weight: 3
        $x_3_4 = "DecryptByte" ascii //weight: 3
        $x_3_5 = "EncryptString" ascii //weight: 3
        $x_3_6 = "DecryptString" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_MA_2147819640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.MA!MTB"
        threat_id = "2147819640"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fb fa 63 47 8c 7e ?? e6 e2 e6 08}  //weight: 5, accuracy: Low
        $x_5_2 = {bc 10 40 00 4c d7 40 00 04 36 40 00 f4 35 40 00 14 36 40 00 b8 36 40 00 1c d0 40 00 88 1d 40 00 c0 29 40 00 0a 11 40 00 da 10 40}  //weight: 5, accuracy: High
        $x_1_3 = "Process32Next" ascii //weight: 1
        $x_1_4 = "gethostbyname" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_MA_2147819640_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.MA!MTB"
        threat_id = "2147819640"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {be 9b a0 72 68 3b a4 72 dc 9b a0 72 b7 70 a2 72 a0 25 a1 72 59 b2 a0 72 f7 e0 a0 72 e2 6f a2 72 b9 7d a2 72 74 9b a0 72 fd a0 94 72 61 b2 a0 72 87 9b a0 72 85 9a a0 72 df 47 a2 72 db 7d a3 72 26 7e a2 72 d1 97 a1 72 e9 8f a2 72 5d d0 a3 72}  //weight: 5, accuracy: High
        $x_5_2 = {ff 25 30 10 40 00 ff 25 2c 10 40 00 ff 25 14 10 40 00 ff 25 00 10 40 00 ff 25 08 10 40 00 ff 25 04 10 40 00 ff 25 4c 10 40 00 ff 25 58 10 40}  //weight: 5, accuracy: High
        $x_1_3 = "Zombie_GetTypeInfo" ascii //weight: 1
        $x_1_4 = "yyLWUOjEncpVgWglQKpjdAU" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_BAD_2147925685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.BAD!MTB"
        threat_id = "2147925685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {b9 0c fe 19 5b 01 cb fe 48 a8 30 d9 47 15 7a 9d cc 43 72}  //weight: 3, accuracy: High
        $x_2_2 = {25 66 f1 46 90 35 be f4 5a 4c 08 91 e7 e0 ee 57}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_BSA_2147927432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.BSA!MTB"
        threat_id = "2147927432"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\dark eye\\Dark EYE" ascii //weight: 10
        $x_1_2 = "vermi.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VBInject_BSA_2147927432_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.BSA!MTB"
        threat_id = "2147927432"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b ec 83 ec 08 68 66 11 40 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 81 ec 38 01 00 00 53 56 57 89 65 f8 c7 45 fc 48}  //weight: 10, accuracy: High
        $x_5_2 = "Regeleingang" ascii //weight: 5
        $x_5_3 = "FernostabteilungR" ascii //weight: 5
        $x_5_4 = "MFdchenkrcnzeD" ascii //weight: 5
        $x_5_5 = "KFseschnitzeln" ascii //weight: 5
        $x_5_6 = "Landesausstellungsgeb" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_BSA_2147927432_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.BSA!MTB"
        threat_id = "2147927432"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 85 e0 fe ff ff 89 45 ec 8b 4d ec b8 c6 04 00 00 3b c8 0f 8f 46}  //weight: 10, accuracy: High
        $x_5_2 = "Piezokeramikbauteile3" ascii //weight: 5
        $x_5_3 = "hrungsversuchs" ascii //weight: 5
        $x_5_4 = "Beispielworts7" ascii //weight: 5
        $x_5_5 = "Krisenkartell8" ascii //weight: 5
        $x_5_6 = "Kaiserbaracken" ascii //weight: 5
        $x_5_7 = "Behelligendes3" ascii //weight: 5
        $x_5_8 = "Pflegetiere6" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_NIT_2147929716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.NIT!MTB"
        threat_id = "2147929716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 ce 00 10 40 00 [0-48] ad [0-48] bb 54 8b ec 83 [0-48] 43 [0-48] 39 18 [0-48] 75 [0-48] bb eb 0c 56 8d [0-48] 39 58 04 [0-48] 75}  //weight: 2, accuracy: Low
        $x_1_2 = "VBA6.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_EM_2147932658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.EM!MTB"
        threat_id = "2147932658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks /delete /tn" ascii //weight: 1
        $x_1_2 = "taskkill /f /im winws.exe" ascii //weight: 1
        $x_1_3 = "Cmd /x/c taskkill /f /im" ascii //weight: 1
        $x_1_4 = "cmd /c timeout /t 1 && start" ascii //weight: 1
        $x_1_5 = "Launcher for Zapret New\\Project1.vbp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_MBQ_2147933332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.MBQ!MTB"
        threat_id = "2147933332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fc 22 40 00 00 f8 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 18 22 40 00 10 22 40 00 24 18 40 00 78 00 00 00 81 00 00 00 8a 00 00 00 8b [0-33] 50 72 6f 6a 65 63 74 31 00 50 72 6f 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBInject_EN_2147933737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBInject.EN!MTB"
        threat_id = "2147933737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Quintises.vbp" wide //weight: 1
        $x_1_2 = "system /v disableregistrytools /t reg_dword" wide //weight: 1
        $x_1_3 = "system /v DisableTaskMgr /t reg_dword" wide //weight: 1
        $x_1_4 = "Users\\Roda" wide //weight: 1
        $x_1_5 = "S8H91EdEA" wide //weight: 1
        $x_1_6 = "dsFxkZoI8" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

