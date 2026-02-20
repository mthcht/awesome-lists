rule Trojan_Win32_Coroxy_MR_2147771335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coroxy.MR!MTB"
        threat_id = "2147771335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 0c 30 [0-2] 81 fb [0-4] 47 3b fb 81 fb [0-4] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coroxy_SIB_2147805593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coroxy.SIB!MTB"
        threat_id = "2147805593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7d 10 00 74 ?? 8b 55 10 88 02 8a 07 30 02 ff 45 10 eb ?? 30 07 49 83 7d 0c ?? 75 ?? 83 7d 10 00 75 ?? 66 83 7f ?? 00 74}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 75 08 c7 45 ?? ?? ?? ?? ?? 33 c0 33 db 8a 1e 46 80 fb 30 72 0f 80 fb 39 77 0a 80 eb 30 f7 65 00 03 c3 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {33 db 8b 75 0c 36 8a 94 29 ?? ?? ?? ?? 02 04 3b 02 c2 36 8a b4 28 01 36 88 b4 29 01 36 88 94 28 01 fe c1 fe c3 4e 74 ?? 36 8a 94 29 01 02 04 3b 02 c2 36 8a b4 28 01 36 88 b4 29 01 36 88 94 28 01 fe c1 75 ?? 8b 7d 14 8b 75 10 85 ff 74 ?? 33 c0 33 d2 33 c9 33 db fe c3 36 8a 94 2b 01 02 c2 36 8a 8c 28 01 36 88 8c 2b 01 36 88 94 28 01 02 ca 36 8a 8c 29 01 30 0e 46 4f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coroxy_DA_2147835692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coroxy.DA!MTB"
        threat_id = "2147835692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d8 8b 45 d8 89 18 8b 45 cc 03 45 ac 2d ?? ?? ?? ?? 03 45 e8 8b 55 d8 31 02 83 45 e8 04 83 45 d8 04 8b 45 e8 3b 45 d4 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coroxy_DA_2147835692_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coroxy.DA!MTB"
        threat_id = "2147835692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e8 8b 55 ec 01 02 8b 45 d8 03 45 b0 03 45 e8 89 45 b4 ?? ?? ?? ?? ?? ?? ?? 8b d8 03 5d b4 ?? ?? ?? ?? ?? ?? ?? 2b d8 8b 45 ec 31 18 ?? ?? ?? ?? ?? ?? ?? 8b 55 e8 83 c2 04 03 c2 89 45 e8 ?? ?? ?? ?? ?? ?? ?? 83 c0 04 01 45 ec 8b 45 e8 3b 45 e4 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coroxy_MA_2147839828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coroxy.MA!MTB"
        threat_id = "2147839828"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 07 d2 f1 fe c1 81 c7 04 00 00 00 66 0f 43 ce 33 c3 0f ac ea 3a f7 d8 80 c5 2f d2 e9 d3 e1 35}  //weight: 5, accuracy: High
        $x_5_2 = {e9 1a 93 46 00 8b 0f 81 c7 04 00 00 00 33 cb d1 c9 99 81 e9 2e 16 83 7d c1 c9 03 49 03 c6 33 d9}  //weight: 5, accuracy: High
        $x_2_3 = "rundll" ascii //weight: 2
        $x_2_4 = "GetUserNameExA" ascii //weight: 2
        $x_2_5 = "socks32.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coroxy_BL_2147840747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coroxy.BL!MTB"
        threat_id = "2147840747"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "socks5" ascii //weight: 1
        $x_1_3 = "powershell.exe -windowstyle hidden -Command" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coroxy_MK_2147841134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coroxy.MK!MTB"
        threat_id = "2147841134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 99 f7 be ?? ?? ?? ?? 89 96 ?? ?? ?? ?? 8b 56 ?? 8b ae ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 96 ?? ?? ?? ?? 69 45 ?? ?? ?? ?? ?? 3b c7 74 ?? 8b 5e ?? 8b 8e ?? ?? ?? ?? 8b 43 ?? 47 05 ?? ?? ?? ?? 33 c8 89 8e ?? ?? ?? ?? 69 45 ?? ?? ?? ?? ?? 3b f8 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coroxy_MI_2147841135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coroxy.MI!MTB"
        threat_id = "2147841135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 99 f7 be ?? ?? ?? ?? 89 96 ?? ?? ?? ?? ba ?? ?? ?? ?? 8b ae ?? ?? ?? ?? 8b 45 ?? 2d ?? ?? ?? ?? 89 03 8b 9e ?? ?? ?? ?? 69 43 ?? ?? ?? ?? ?? 3b c2 74 ?? 8b be ?? ?? ?? ?? 8b 4e ?? 81 c7 ?? ?? ?? ?? 0f 1f 40 ?? 33 cf 42 89 4e ?? 69 43 ?? ?? ?? ?? ?? 3b d0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coroxy_XY_2147844095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coroxy.XY!MTB"
        threat_id = "2147844095"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 c2 eb 00 36 8a 8c 28 00 fc ff ff eb 40}  //weight: 1, accuracy: High
        $x_1_2 = {36 88 8c 2b 00 fc ff ff e9 54 ff ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {36 88 94 28 00 fc ff ff e9 73 ff ff ff}  //weight: 1, accuracy: High
        $x_1_4 = {02 ca e9 e5 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {36 8a 8c 29 00 fc ff ff eb bb}  //weight: 1, accuracy: High
        $x_1_6 = {30 0e eb 34}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coroxy_UU_2147847391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coroxy.UU!MTB"
        threat_id = "2147847391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 c7 04 24 ?? ?? ?? ?? 8b 44 24 ?? 83 2c 24 04 01 04 24 8b 04 24 31 01}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d3 c1 ea ?? 03 f3 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 8d 44 24 ?? 50 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 31 74 24 ?? 8b 44 24 ?? 31 44 24 ?? 2b 7c 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coroxy_PBI_2147849189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coroxy.PBI!MTB"
        threat_id = "2147849189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 57 89 c6 89 d7 89 c8 39 f7 8d 74 31 ?? 8d 7c 39 ?? c1 f9 02 78 ?? fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 d8 89 18 e8 ?? ?? ?? ?? 8b 5d cc 03 5d ac 81 eb ?? ?? ?? ?? 03 5d e8 2b d8 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 31 18 83 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coroxy_MB_2147851522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coroxy.MB!MTB"
        threat_id = "2147851522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {7f d5 7c 75 77 cb 49 6c 72 c8 6b 00 96 a7 08 00 96 a7 5e 69 64 d3 7d 61 72 e1 7a 65 73 a7 08 00 96 a7 08 00 96 f2 66 6d 37 d7 5e 69 33 d0 47 66}  //weight: 5, accuracy: High
        $x_5_2 = {c3 6d 48 b7 c5 6c 6c b3 e8 08 00 96 ee 6d 74 db c6 6c 75 b2 cc 40 61 a8 cb 64 65 69 a7 08 00 55 d9 6d 61 8a cc 4e 69 6a cc 49 00 96 a7 08 00 96}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coroxy_SK_2147852839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coroxy.SK!MTB"
        threat_id = "2147852839"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b d0 8b 45 d8 31 10 6a 00 e8 9b 7a f3 ff ba 04 00 00 00 2b d0 01 55 e8 6a 00 e8 8a 7a f3 ff ba 04 00 00 00 2b d0 01 55 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coroxy_GPC_2147893442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coroxy.GPC!MTB"
        threat_id = "2147893442"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {46 8a 04 3b 30 06 7a 04 7b 02 61 14 46 43 49 3b 5d 0c}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coroxy_YAA_2147897329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coroxy.YAA!MTB"
        threat_id = "2147897329"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5d cc 03 5d ac 03 5d e8 2b d8 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 d8 31 18 83 45 e8 04 83 45 d8 04 8b 45 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coroxy_XZ_2147903209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coroxy.XZ!MTB"
        threat_id = "2147903209"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HOST1:94.156.69.109" ascii //weight: 1
        $x_1_2 = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" ascii //weight: 1
        $x_1_3 = "powershell.exe -windowstyle hidden -Command" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coroxy_YAB_2147903487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coroxy.YAB!MTB"
        threat_id = "2147903487"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 31 18 83 45 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coroxy_MKZ_2147919402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coroxy.MKZ!MTB"
        threat_id = "2147919402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {fe c3 36 8a 94 2b 00 fc ff ff 02 c2 36 8a 8c 28 00 fc ff ff 36 88 8c 2b 00 fc ff ff 36 88 94 28 00 fc ff ff 02 ca 36 8a 8c 29 00 fc ff ff 30 0e 46 4f 75 cc}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coroxy_YBN_2147923081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coroxy.YBN!MTB"
        threat_id = "2147923081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "socks5" ascii //weight: 1
        $x_10_2 = {8a 04 3b 30 06 46 43}  //weight: 10, accuracy: High
        $x_1_3 = {50 68 7e 66 04 80 ff 75 fc e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coroxy_MKW_2147923893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coroxy.MKW!MTB"
        threat_id = "2147923893"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 04 3b 30 06 46 43 49 3b 5d 0c 75 02}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Coroxy_GA_2147924835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coroxy.GA!MTB"
        threat_id = "2147924835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 3b 30 06 46 43 49 80 fb 28 75}  //weight: 1, accuracy: High
        $x_1_2 = {02 ca 36 8a 8c 29 00 fc ff ff 30 0e 46 4f 75 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Coroxy_MKX_2147963447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coroxy.MKX!MTB"
        threat_id = "2147963447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 c2 36 8a 8c 28 80 fe ff ff 36 88 8c 2b 80 fe ff ff 36 88 94 28 80 fe ff ff 02 ca 36 8a 8c 29 80 fe ff ff 30 0e 46 4f 0b ff 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

