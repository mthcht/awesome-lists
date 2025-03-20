rule Trojan_Win32_AsyncRAT_BH_2147838608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRAT.BH!MTB"
        threat_id = "2147838608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f6 a4 c5 4e 52 b2 70 44 88 a8 80 05 1e 78 66 cc 80 74 83 d9 f9 cc 34 93 25 a2 04 74 b8 5a b5 46 33 8d a9 21 a8 be 02 ce a6 e0}  //weight: 1, accuracy: High
        $x_1_2 = {c0 b4 4c 8b dd 22 87 f8 f7 ae 3d 1f 12 e5 10 10 30 01 67 a1 e8 87 9f c4 17 3d 4e 81 bd 82 42 1e e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRAT_GFF_2147841702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRAT.GFF!MTB"
        threat_id = "2147841702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 84 3c ?? ?? ?? ?? 88 84 34 ?? ?? ?? ?? 88 8c 3c ?? ?? ?? ?? 0f b6 84 34 ?? ?? ?? ?? 8b 4c 24 14 03 c2 0f b6 c0 0f b6 84 04 ?? ?? ?? ?? 30 04 0b 43 3b 5c 24 10 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRAT_A_2147842981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRAT.A!MTB"
        threat_id = "2147842981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 44 24 10 12 00 00 00 e8 ?? 93 fb ff 8b 44 24 14 8b 4c 24 18 8b 15 e8 ?? ?? 00 8b 1d ec ?? ?? 00 89 14 24 89 5c 24 04 89 44 24 08 89 4c 24 0c e8 ?? 4f ff ff 8b 44 24 14 8b 4c 24 10}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRAT_EAP_2147844814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRAT.EAP!MTB"
        threat_id = "2147844814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {97 a6 69 65 9c 72 06 3e 32 f7 46 29 b3 58 6c 61 81 23 d2 b9 2c 9b 32 81 27 d8 42 ae b2 83 2b d4 23 0b d2 23 b7 78 82 1c 68 81 fe e2}  //weight: 2, accuracy: High
        $x_2_2 = {86 43 38 90 65 3f 65 83 38 00 41 11 d4 40 11 fa 82 74 8a 6f 39 aa 4a 17 2a e0 17 2c 81 1a 5c e7 11 71 07 2b cb 63 92 26 e9 3a ee 31 78 3a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRAT_B_2147849121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRAT.B!MTB"
        threat_id = "2147849121"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 04 11 32 05 ?? ?? ?? ?? 8b 4d ?? 8b 11 8b 4a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRAT_C_2147851246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRAT.C!MTB"
        threat_id = "2147851246"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b d0 8a 82 ?? ?? ?? ?? 88 44 0c 30 41 81 f9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRAT_MBHL_2147852236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRAT.MBHL!MTB"
        threat_id = "2147852236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6f 00 72 00 5f 00 5f 00 31 00 2d ?? ?? ?? ?? 00 33 00 37 00 37}  //weight: 1, accuracy: Low
        $x_1_2 = {c4 43 40 00 bf f5 73 01 00 ff ff ff 08 00 00 00 01 00 00 00 19 00 05 00 e9 00 00 00 70 93 40 00 40 9b 40 00 88 28 40 00 78}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRAT_MBHK_2147852450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRAT.MBHK!MTB"
        threat_id = "2147852450"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 a0 c1 e0 06 8b 4d a0 8b 55 dc 89 04 8a 8b 45 a0 c1 e0 0c 8b 4d a0 8b 55 b4 89 04 8a 8b 45 a0 c1 e0 12}  //weight: 1, accuracy: High
        $x_1_2 = {60 18 40 00 10 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 80 16 40 00 00 16 40 00 c4 14 40 00 78 00 00 00 7f 00 00 00 86 00 00 00 87}  //weight: 1, accuracy: High
        $x_1_3 = {42 42 f6 57 df 42 00 42 42 f6 57 df 42 00 00 42 42 f6 57 df 42 00 00 00 01 00 00 00 f4 1c 40 00 00 00 00 00 2c 27 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRAT_DAX_2147888521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRAT.DAX!MTB"
        threat_id = "2147888521"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 00 00 84 3d af 15 5b e1 2e 49 80 2f 64 9d 1b 15 09 66 9a da 12 8d 35 02 3a 46 b1 18 e9 87 23 f0 39 75 3a 4f ad 33 99 66 cf 11 b7}  //weight: 1, accuracy: High
        $x_1_2 = {bb 4f 8e 27 d1 e5 28 8a 54 7e 21 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 43 6c 61 73 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRAT_DV_2147895571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRAT.DV!MTB"
        threat_id = "2147895571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 68 ?? 67 42 00 ff 15 48 c1 41 00 8b d8 85 db 75 1b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRAT_D_2147898414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRAT.D!MTB"
        threat_id = "2147898414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 34 39 f7 e9 03 d1 c1 fa ?? 8b c2 c1 e8 ?? 03 c2 0f be c0 6b c0 ?? 2a c8 80 c1 ?? 30 0e 8b 4d}  //weight: 2, accuracy: Low
        $x_1_2 = "ProcessorNameString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRAT_E_2147898770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRAT.E!MTB"
        threat_id = "2147898770"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 2f 88 8b ?? ?? ?? ?? ?? 80 07 49 ?? ?? ?? ?? ?? ?? f6 2f 47 e2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRAT_EM_2147900272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRAT.EM!MTB"
        threat_id = "2147900272"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks /Create /SC MINUTE /MO 15 /TN" ascii //weight: 1
        $x_1_2 = "MyLoader.bat" ascii //weight: 1
        $x_1_3 = "CollapseCheck_protectedv.exe" ascii //weight: 1
        $x_1_4 = "C:\\Path\\To\\YourApp.exe" ascii //weight: 1
        $x_1_5 = "Awdftg4grg5g5bf45hrgefeg4rgt4brh55rbdgdg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRAT_ASB_2147901201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRAT.ASB!MTB"
        threat_id = "2147901201"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "cw.rowlqig.cn" ascii //weight: 2
        $x_1_2 = "Users\\Public\\Downloads\\%s" ascii //weight: 1
        $x_1_3 = "SNwintvaanae" ascii //weight: 1
        $x_1_4 = "sandbox!!!" ascii //weight: 1
        $x_2_5 = {6a 00 68 80 00 00 00 6a 04 6a 00 6a 01 68 00 00 00 80 68 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 89 45 f8 6a 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRAT_G_2147901524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRAT.G!MTB"
        threat_id = "2147901524"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {ff 8b f0 ff 75}  //weight: 2, accuracy: High
        $x_2_2 = {ff 8a 1e 32 18 ff 75}  //weight: 2, accuracy: High
        $x_2_3 = {ff 88 18 8b 45 d0 83 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRAT_F_2147901998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRAT.F!MTB"
        threat_id = "2147901998"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6c ff 6c 70 ff fc 90 6c 68 ff 6c 74 ff fc 90 fb 11 6c 6c ff 6c 70 ff fc a0 6c 68 ff f5 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRAT_ARAQ_2147908939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRAT.ARAQ!MTB"
        threat_id = "2147908939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "7>\\+D7r4(qHc@3w95'Dd)gutJ$.resources" ascii //weight: 10
        $x_2_2 = "GetExecutingAssembly" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRAT_DB_2147936521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRAT.DB!MTB"
        threat_id = "2147936521"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "54"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "Convert]::FromBase64String($" wide //weight: 1
        $x_1_3 = "DownloadData($" wide //weight: 1
        $x_50_4 = "[System.Reflection.Assembly]::Load($" wide //weight: 50
        $x_1_5 = "net.webclient" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

