rule Trojan_Win64_Emotetcrypt_A_2147799424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.A!MTB"
        threat_id = "2147799424"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SreismeoW" ascii //weight: 1
        $x_1_2 = "epnecggzglkpilam" ascii //weight: 1
        $x_1_3 = "fyqzxuvfgwjwyuk" ascii //weight: 1
        $x_1_4 = {4c 63 c6 4d 8d 49 01 49 8b c3 ff c6 49 f7 e0 48 d1 ea 48 6b ca 0b 4c 2b c1 42 0f b6 4c 84 50 41 30 49 ff 81 fe 00 ca 02 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_FJ_2147811792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.FJ!MTB"
        threat_id = "2147811792"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "mzonudt.dll" ascii //weight: 10
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "RaiseException" ascii //weight: 1
        $x_1_6 = "bffmjtmmsvsdwnt" ascii //weight: 1
        $x_1_7 = "ckiarmaidueommyn" ascii //weight: 1
        $x_1_8 = "dvgfbvznupyzben" ascii //weight: 1
        $x_1_9 = "eqkznoqmzvalqsrf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_FK_2147811842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.FK!MTB"
        threat_id = "2147811842"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "zqdgmajtsujbmk.dll" ascii //weight: 10
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "RaiseException" ascii //weight: 1
        $x_1_6 = "bedvrfomatbxsus" ascii //weight: 1
        $x_1_7 = "bgrvenghhlcnme" ascii //weight: 1
        $x_1_8 = "fruezveinljyitrz" ascii //weight: 1
        $x_1_9 = "ghxzlxwmtxpfmvh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_FM_2147811897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.FM!MTB"
        threat_id = "2147811897"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "zmtspqwn.dll" ascii //weight: 10
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "RaiseException" ascii //weight: 1
        $x_1_6 = "efqntyyjqlxfzww" ascii //weight: 1
        $x_1_7 = "ilahmnpokpozoqlzp" ascii //weight: 1
        $x_1_8 = "jbhjptzodogewlem" ascii //weight: 1
        $x_1_9 = "jlnyjommxgwikwvd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_FN_2147811913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.FN!MTB"
        threat_id = "2147811913"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "fsmaslyxoptouyrcngvph.dll" ascii //weight: 10
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "RaiseException" ascii //weight: 1
        $x_1_6 = "afelwfzryprvcrv" ascii //weight: 1
        $x_1_7 = "anauxeabrmuive" ascii //weight: 1
        $x_1_8 = "clzrfuvemniqefco" ascii //weight: 1
        $x_1_9 = "fyvjbytdlpqxngu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_FS_2147812005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.FS!MTB"
        threat_id = "2147812005"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllMain" ascii //weight: 10
        $x_1_2 = "fzscscugjay.dll" ascii //weight: 1
        $x_1_3 = "aqgxsphgjijetfluv" ascii //weight: 1
        $x_1_4 = "arinkhfsfyidivnek" ascii //weight: 1
        $x_1_5 = "dujoocyfecngsjzmx" ascii //weight: 1
        $x_1_6 = "gxyxhwadrouvuvmov" ascii //weight: 1
        $x_1_7 = "zuicmtnm.dll" ascii //weight: 1
        $x_1_8 = "agjyzxlknkerqkvv" ascii //weight: 1
        $x_1_9 = "akihdppydchaodlpa" ascii //weight: 1
        $x_1_10 = "cwiqbgagdoqoeyihz" ascii //weight: 1
        $x_1_11 = "cyvjdzssogxttidz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Emotetcrypt_FT_2147812006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.FT!MTB"
        threat_id = "2147812006"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "K5W8jnX2tH4bgN4cIcqvL54Djk2vqy6LsbOh4T5fU" ascii //weight: 1
        $x_1_2 = "LookBeautifully" ascii //weight: 1
        $x_1_3 = "LeaveClose" ascii //weight: 1
        $x_1_4 = "bdtazrcwtjchftrgn" ascii //weight: 1
        $x_1_5 = "chmixrgixfqmfjjdi" ascii //weight: 1
        $x_1_6 = "ftahjfetmrxkqpnez" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_JK_2147817146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.JK!MTB"
        threat_id = "2147817146"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 01 8b 4c 24 04 33 c8 8b c1 8b 0d ?? ?? ?? ?? 8b 14 24 03 d1 8b ca 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 2b ca 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 03 ca 48 63 c9 48 8b 54 24 28 88 04 0a e9}  //weight: 1, accuracy: Low
        $x_1_2 = "z^gff0IGJrphvLm4LXL+AAbh$XK??@FhgGIO>0&jRt$_jO8shk$D^%5zx?2l" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotetcrypt_JM_2147817195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.JM!MTB"
        threat_id = "2147817195"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 8a c5 83 c7 01 83 e0 3f 48 63 ef 49 03 c0 8a 04 10 32 01 48 83 c1 01 88 06 48 83 c6 01 49 3b ec 72}  //weight: 1, accuracy: High
        $x_10_2 = "DllRegisterServer" ascii //weight: 10
        $x_1_3 = "sN2ak&7_vY+_4!Qy1IWvYXGMNk@czXS>e)LeD4k<g4bPvxZrf_c0dLmsJem2X8o" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Emotetcrypt_JN_2147817220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.JN!MTB"
        threat_id = "2147817220"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 b8 8f e3 38 8e e3 38 8e e3 41 83 c2 01 49 f7 e1 48 c1 ea 04 48 8d 04 d2 48 03 c0 4c 2b c8 4c 03 ce 41 8a 04 29 4d 63 ca 41 32 00 49 83 c0 01 41 88 03 49 83 c3 01 4c 3b cb 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_AM_2147817271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.AM!MTB"
        threat_id = "2147817271"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {ff c3 49 f7 e3 49 8b c3 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 05 48 6b c0 3e 4c 2b d8 4c 03 dd 43 8a 04 23 4c 63 db 41 32 00 49 ff c0 88 01}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_AM_2147817271_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.AM!MTB"
        threat_id = "2147817271"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {48 03 4c 24 38 0f b6 04 01 8b 4c 24 04 33 c8 8b c1 8b 0d}  //weight: 3, accuracy: High
        $x_3_2 = {48 8b 4c 24 20 0f b6 04 01 89 44 24 04 48 63 0c 24 33 d2 48 8b c1 48 f7 74 24 40 48 8b c2}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_JO_2147817292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.JO!MTB"
        threat_id = "2147817292"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 03 c1 48 63 0d ?? ?? ?? ?? 48 2b c1 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 48 63 c9 48 03 c1 48 63 0d ?? ?? ?? ?? 48 03 c1 48 63 0d ?? ?? ?? ?? 48 03 c1 48 63 0d ?? ?? ?? ?? 48 03 4c 24 38 0f b6 04 01 8b 4c 24 04 33 c8 8b c1 8b 0d ?? ?? ?? ?? 8b 14 24 2b d1 8b ca}  //weight: 1, accuracy: Low
        $x_10_2 = "DllRegisterServer" ascii //weight: 10
        $x_1_3 = "0dh8C8w!eb##?(eCfkhtSs4tq9>8NnkEQKen@z" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Emotetcrypt_JQ_2147817357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.JQ!MTB"
        threat_id = "2147817357"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 03 c8 48 63 05 ?? ?? ?? ?? 48 03 c8 8b 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 48 98 48 2b c8 48 8b 44 24 38 0f b6 04 08 44 33 c0 8b 05 ?? ?? ?? ?? 8b 0c 24 03 c8 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? 03 c1 03 d0 8b 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 2b d0}  //weight: 1, accuracy: Low
        $x_1_2 = "6y0KW$aaYzBVMG7YrXUPm4M&ZR&4aW8!C<g7*c!?i5d)A&@D%&8^l4LeJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotetcrypt_JR_2147817358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.JR!MTB"
        threat_id = "2147817358"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 b8 0d ce c7 e0 7c 0c ce c7 ff c7 49 f7 e3 48 c1 ea 05 48 6b d2 29 4c 2b da 4d 03 d8 4d 03 df 4d 03 dd 43 8a 04 33 4c 63 df 32 01 48 ff c1 88 06 48 ff c6 4c 3b db 72}  //weight: 1, accuracy: High
        $x_10_2 = "DllRegisterServer" ascii //weight: 10
        $x_1_3 = "^6v+xjeaw?07!0cFF@FUOBwO)v$qSp6i0OFQAX@h" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Emotetcrypt_EA_2147817422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.EA!MTB"
        threat_id = "2147817422"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 98 48 8b 4c 24 20 0f b6 04 01 89 44 24 04 48 63 0c 24 33 d2 48 8b c1 48 f7 74 24 40 48 8b c2}  //weight: 5, accuracy: High
        $x_5_2 = {48 63 c9 48 2b c1 48 8b 4c 24 38 0f b6 04 01 8b 4c 24 04 33 c8 8b c1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_EB_2147817423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.EB!MTB"
        threat_id = "2147817423"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 2b c1 48 8b 4c 24 38 0f b6 04 01 8b 4c 24 04 33 c8 8b c1}  //weight: 5, accuracy: High
        $x_5_2 = {44 03 c1 41 8b c8 03 d1 8b ca}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_JS_2147817485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.JS!MTB"
        threat_id = "2147817485"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b ca 48 2b c8 8b 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 48 98 48 2b c8 48 63 05 ?? ?? ?? ?? 48 2b c8 8b 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 48 98 48 2b c8 48 8b 44 24 38 0f b6 04 08 44 33 c0 8b 05 ?? ?? ?? ?? 8b 0c 24 03 c8 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? 03 c1 03 d0}  //weight: 1, accuracy: Low
        $x_10_2 = "DllRegisterServer" ascii //weight: 10
        $x_1_3 = "2p$>)Z^IV^aoA8%0a95SSkN@m" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Emotetcrypt_JT_2147817566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.JT!MTB"
        threat_id = "2147817566"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af c2 48 98 49 8d 14 01 48 8b 45 28 48 01 d0 0f b6 00 44 31 c0 88 01 83 45 fc 01 8b 45 fc 48 98 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af d1 48 63 d2 48 8b 4d 20 48 29 d1 8b 15 ?? ?? ?? ?? 48 63 d2 48 29 d1 8b 15 ?? ?? ?? ?? 48 63 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_EC_2147817625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.EC!MTB"
        threat_id = "2147817625"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 03 c1 48 63 4c 24 70 48 2b c1 48 8b 4c 24 60 0f b6 04 01 2b 44 24 20 8b 4c 24 04 33 c8 8b c1}  //weight: 5, accuracy: High
        $x_5_2 = {0f af 54 24 28 03 ca 48 63 c9 48 8b 54 24 50 88 04 0a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_ED_2147817626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.ED!MTB"
        threat_id = "2147817626"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4d 03 c1 4d 03 c0 49 2b ca 48 03 cd 49 2b d0 46 8a 04 2a 46 32 04 39 49 8d 0c 31 48 0f af c8}  //weight: 5, accuracy: High
        $x_5_2 = {49 0f af c2 48 2b c1 49 03 c3 48 03 c5 48 ff c5 46 88 04 30}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_JU_2147817691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.JU!MTB"
        threat_id = "2147817691"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 2b c8 8b 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 48 98 48 2b c8 48 63 05 ?? ?? ?? ?? 48 2b c8 48 8b 44 24 48 0f b6 04 08 03 44 24 30 41 8b d0 33 d0 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 04 24 2b c1 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 2b c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_JV_2147817709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.JV!MTB"
        threat_id = "2147817709"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 b8 5f 43 79 0d e5 35 94 d7 41 83 c2 01 49 f7 e1 48 c1 ea 04 48 6b d2 13 4c 2b ca 4c 2b ce 4d 2b cc 4c 2b cf 4d 2b c8 4c 2b cd 4d 03 cd 41 8a 04 09 4d 63 ca 41 32 03 49 83 c3 01 88 03 48 83 c3 01 4d 3b ce 72}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 44 24 48 0f b6 04 08 03 44 24 30 41 8b d0 33 d0 8b 0d ?? ?? ?? ?? 8b 04 24 2b c1 2b 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 48 63 c8 48 8b 44 24 38 88 14 08 e9}  //weight: 1, accuracy: Low
        $x_1_3 = {44 32 04 01 49 8d 45 01 49 8d 49 01 49 0f af ce 49 0f af c5 48 03 c0 48 2b d0 48 83 c1 01 49 0f af cb 49 0f af d7 49 03 ca 48 8d 04 16 48 03 cb 48 83 c6 01 48 8d 0c 48 48 8b 44 24 78 48 89 b4 24 80 00 00 00 44 88 04 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotetcrypt_JW_2147817746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.JW!MTB"
        threat_id = "2147817746"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 c9 48 2b c1 48 63 0d ?? ?? ?? ?? 48 03 4c 24 48 0f b6 04 01 03 44 24 30 8b 4c 24 04 33 c8 8b c1 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 14 24 2b d1 8b ca 03 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 2b ca 03 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 2b ca}  //weight: 1, accuracy: Low
        $x_1_2 = "sU1vabY@3>DFyUtcf)9$^+Vl6irbD>olEE^<$@PWUjsR0M+Ks#jlmrXg%TE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotetcrypt_JX_2147817757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.JX!MTB"
        threat_id = "2147817757"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 2b c8 48 63 05 ?? ?? ?? ?? 48 03 c8 48 63 05 ?? ?? ?? ?? 48 03 c8 48 63 05 ?? ?? ?? ?? 48 03 c8 48 63 05 ?? ?? ?? ?? 48 03 c8 8b 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 48 98 48 2b c8 48 63 05 ?? ?? ?? ?? 48 2b c8 48 8b 44 24 38 0f b6 04 08 41 8b d0 33 d0 8b 0d ?? ?? ?? ?? 8b 04 24 03 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {48 98 48 03 c8 8b 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 48 98 48 03 c8 48 63 05 ?? ?? ?? ?? 48 03 c8 48 63 05 ?? ?? ?? ?? 48 2b c8 48 63 05 ?? ?? ?? ?? 48 2b c8 48 8b 44 24 48 0f b6 04 08 03 44 24 30 41 8b d0 33 d0 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 04 24 2b c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotetcrypt_PC_2147817767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.PC!MTB"
        threat_id = "2147817767"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "B^%R5$$?t*dR0R_)r" ascii //weight: 2
        $x_1_2 = {48 8b 8c 24 ?? ?? ?? ?? 0f b6 04 01 8b 8c 24 ?? ?? ?? ?? 33 c8 8b c1 8b 0d ?? ?? ?? ?? 8b 94 24 ?? ?? ?? ?? 03 d1 8b ca}  //weight: 1, accuracy: Low
        $x_1_3 = {ff c0 89 84 24 ?? ?? ?? ?? 48 63 84 24 ?? ?? ?? ?? 48 3b 84 24 ?? ?? ?? ?? 0f 83 ?? ?? ?? ?? 48 63 84 24 ?? ?? ?? ?? 48 8b 8c 24 ?? ?? ?? ?? 0f b6 04 01 89 84 24 ?? ?? ?? ?? 8b 84 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_JY_2147817921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.JY!MTB"
        threat_id = "2147817921"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af d1 48 63 d2 4c 89 c1 48 29 d1 8b 15 ?? ?? ?? ?? 48 63 d2 4c 8d 04 11 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af d1 48 63 d2 49 01 d0 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af d1 48 63 d2 4c 89 c1 48 29 d1 8b 15 ?? ?? ?? ?? 48 63 d2 48 01 d1 8b 15 ?? ?? ?? ?? 48 63 d2 48 01 d1 8b 15 ?? ?? ?? ?? 48 63 d2 48 29 d1 8b 15 ?? ?? ?? ?? 48 63 d2 48 29 d1 8b 15 60 7b 01 00 48 63 d2 48 29 d1 48 89 ca 48 39 d0 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_JZ_2147817926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.JZ!MTB"
        threat_id = "2147817926"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af c2 48 98 4c 89 ca 48 29 c2 48 8b 45 28 48 01 d0 0f b6 00 44 31 c0 88 01 83 45 fc 01 8b 45 fc 48 98 8b 15 ?? ?? ?? ?? 48 63 ca 48 8b 55 20 48 01 d1 8b 15 ?? ?? ?? ?? 48 63 d2 48 29 d1 8b 15 ?? ?? ?? ?? 48 63 d2 48 29 d1 8b 15 ?? ?? ?? ?? 48 63 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_KA_2147818037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.KA!MTB"
        threat_id = "2147818037"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 98 48 29 c2 8b 05 ?? ?? ?? ?? 48 98 48 29 c2 8b 05 ?? ?? ?? ?? 48 98 48 89 d1 48 29 c1 8b 05 ?? ?? ?? ?? 48 63 d0 8b 05 ?? ?? ?? ?? 48 98 48 29 c2 48 89 d0 48 01 c8 4c 01 c0 48 03 45 68 48 03 45 70 48 03 45 78 4c 01 f8 4c 01 f0 4c 01 e8 4c 01 e0 48 01 f8 48 01 f0 48 01 d8 4c 01 d8 4c 01 d0 48 01 c0 49 8d 14 01 8b 05 ?? ?? ?? ?? 48 98 48 01 c0 48 29 c2 8b 05 ?? ?? ?? ?? 48 98 48 01 c0 48 29 c2 48 8b 85 38 01 00 00 48 01 d0 48 89 85 88 00 00 00 c7 85 bc 00 00 00 00 00 00 00 e9}  //weight: 1, accuracy: Low
        $x_1_2 = "Project1.dll" ascii //weight: 1
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_1_4 = "_Z10DecryptXORiPhiS_yS_yi" ascii //weight: 1
        $x_1_5 = "_Z16get_proc_addressiiiiPcPh" ascii //weight: 1
        $x_1_6 = "_Z6AntiAVii" ascii //weight: 1
        $x_1_7 = "adress_payload" ascii //weight: 1
        $x_1_8 = "mem_s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_KB_2147818606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.KB!MTB"
        threat_id = "2147818606"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 63 c7 48 8b c6 49 f7 e0 49 8b c8 48 2b ca 48 d1 e9 48 03 ca 48 c1 e9 05 48 6b c1 35 4c 2b c0 41 0f b6 04 18 43 32 04 0a 41 88 01 ff c7 4d 8d 49 01 81 ff 9d 0b 00 00 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_KC_2147818634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.KC!MTB"
        threat_id = "2147818634"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c0 89 44 24 ?? 8b 44 24 ?? 39 44 24 ?? 7d ?? 48 63 44 24 ?? 0f b6 44 04 ?? 89 44 24 ?? 8b 44 24 ?? 99 b9 ?? ?? ?? ?? f7 f9 8b c2 48 98 48 8b 0d ?? ?? ?? ?? 0f b6 04 01 8b 4c 24 ?? 33 c8 8b c1 48 63 4c 24 ?? 48 8b 54 24 ?? 88 04 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_KD_2147818664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.KD!MTB"
        threat_id = "2147818664"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 89 84 24 ?? ?? ?? ?? 8b 44 24 ?? 39 84 24 ?? ?? ?? ?? 7d ?? 48 63 84 24 ?? ?? ?? ?? 0f b6 bc 04 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 99 b9 ?? ?? ?? ?? f7 f9 48 63 ca 48 8b 05 ?? ?? ?? ?? 0f b6 04 08 8b d7 33 d0 48 63 8c 24 ?? ?? ?? ?? 48 8b 84 24 ?? ?? ?? ?? 88 14 08 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_KE_2147819170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.KE!MTB"
        threat_id = "2147819170"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 89 88 88 88 f7 eb 03 d3 c1 fa 04 8b c2 c1 e8 1f 03 d0 8b c3 ff c3 6b d2 1e 2b c2 48 63 d0 48 8b 05 ?? ?? ?? ?? 8a 14 02 41 32 54 3d 00 88 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_KF_2147819171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.KF!MTB"
        threat_id = "2147819171"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 0c 01 b8 ?? ?? ?? ?? 41 32 4c 3a fd 41 f7 e8 88 4f fe c1 fa 05 8b c2 c1 e8 1f 03 d0 8b c6 83 c6 03 6b d2 41 2b c2 83 c0 02 48 63 c8 48 8b 05 ?? ?? ?? ?? 0f b6 0c 01 41 32 4c 3b fd 49 ff cc 88 4f ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_KG_2147819172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.KG!MTB"
        threat_id = "2147819172"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 d0 48 8b 85 ?? ?? ?? ?? 48 8d 0c 02 8b 85 ?? ?? ?? ?? 48 98 44 0f b6 44 05 a0 4c 8b 0d ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 99 c1 ea 1b 01 d0 83 e0 1f 29 d0 48 98 4c 01 c8 0f b6 00 44 31 c0 88 01 83 85 ?? ?? ?? ?? 01 8b 85 ?? ?? ?? ?? 3b 85 ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_KI_2147819388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.KI!MTB"
        threat_id = "2147819388"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 83 c4 01 41 f7 ed c1 fa 03 8b c2 c1 e8 1f 03 c2 49 63 d5 41 83 c5 01 48 98 48 8d 0c 40 48 8b 05 ?? ?? ?? ?? 48 c1 e1 04 48 03 c8 0f b6 04 0a 42 32 44 27 ff 48 83 ed 01 41 88 44 24 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {49 83 c4 01 41 f7 ed c1 fa 04 8b c2 c1 e8 1f 03 d0 48 8b 05 ?? ?? ?? ?? 48 63 ca 49 63 d5 41 83 c5 01 48 6b c9 31 48 03 c8 0f b6 04 0a 42 32 44 27 ff 48 83 ed 01 41 88 44 24 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotetcrypt_KJ_2147819440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.KJ!MTB"
        threat_id = "2147819440"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 ca 48 6b c9 ?? 49 03 c9 0f b6 4c 01 ?? b8 ?? ?? ?? ?? 41 32 4c 33 ?? 41 f7 e8 88 4e ?? c1 fa ?? 8b c2 c1 e8 ?? 03 d0 48 8b 05 ?? ?? ?? ?? 48 63 ca 48 6b c9 ?? 49 03 c9 0f b6 4c 01 ?? 32 4c 37 ?? 49 83 ec ?? 88 4e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_KK_2147819700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.KK!MTB"
        threat_id = "2147819700"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 eb c1 fa 03 8b c2 c1 e8 1f 03 d0 8b c3 ff c3 8d 0c d2 c1 e1 02 2b c1 48 63 c8 42 8a 04 01 43 32 04 13 41 88 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_KL_2147819931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.KL!MTB"
        threat_id = "2147819931"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 fa 03 8b c2 c1 e8 1f 03 d0 8b c6 83 c6 03 6b d2 ?? 2b c2 83 c0 02 48 63 c8 48 8b 05 ?? ?? ?? ?? 0f b6 0c 01 32 4c 3b ?? 49 ff cc 88 4f ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_KM_2147819977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.KM!MTB"
        threat_id = "2147819977"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 89 84 24 ?? ?? ?? ?? 8b 44 24 ?? 39 84 24 [0-6] 48 63 84 24 ?? ?? ?? ?? 0f b6 7c 04 ?? 8b 84 24 ?? ?? ?? ?? 99 b9 ?? ?? ?? ?? f7 f9 48 63 ca 48 8b 05 ?? ?? ?? ?? 0f b6 04 08 8b d7 33 d0 48 63 8c 24 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 88 14 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_KN_2147820037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.KN!MTB"
        threat_id = "2147820037"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 54 0d ?? 48 8b 0d ?? ?? ?? ?? 44 8b 45 ?? 89 45 b4 44 89 c0 89 55 b0 99 44 8b 45 ?? 41 f7 f8 4c 63 ca 42 0f b6 14 09 44 8b 55 ?? 41 31 d2 45 88 d3 48 8b 8d ?? ?? ?? ?? 4c 63 4d ?? 46 88 1c 09 8b 45 ?? 83 c0 01 89 45 ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_KO_2147820174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.KO!MTB"
        threat_id = "2147820174"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8b 45 18 89 45 b4 44 89 c0 48 89 55 a8 99 44 8b 45 b4 41 f7 f8 4c 63 ca 4c 8b 55 a8 43 0f b6 14 0a 31 d1 41 88 cb 4c 8b 8d ?? ?? ?? ?? 8b 4d 18 2b 4d 1c 03 4d 1c 48 63 f1 45 88 1c 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_KP_2147820295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.KP!MTB"
        threat_id = "2147820295"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c8 c1 f8 ?? 89 d3 29 c3 89 d8 6b c0 ?? 89 ce 29 c6 89 f0 48 98 4c 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 ?? ?? ?? ?? 01 8b 85 ?? ?? ?? ?? 3b 85 ?? ?? ?? ?? 0f 9c c0 84 c0 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_KQ_2147820326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.KQ!MTB"
        threat_id = "2147820326"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 d1 0f b6 4c 15 20 48 8b 15 ?? ?? ?? ?? 44 8b 45 f8 89 45 bc 44 89 c0 48 89 55 b0 99 44 8b 45 bc 41 f7 f8 4c 63 ca 4c 8b 55 b0 43 0f b6 14 0a 31 d1 41 88 cb 4c 8b 8d ?? ?? ?? ?? 8b 4d f8 8b 55 fc 0f af 95 ?? ?? ?? ?? 29 d1 48 63 f1 45 88 1c 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_KR_2147820415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.KR!MTB"
        threat_id = "2147820415"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 4d f0 0f b6 54 0d 00 48 8b 0d ?? ?? ?? ?? 44 8b 45 f0 89 45 b4 44 89 c0 89 55 b0 99 44 8b 45 b4 41 f7 f8 4c 63 ca 42 0f b6 14 09 44 8b 55 b0 41 31 d2 45 88 d3 48 8b 8d ?? ?? ?? ?? 8b 55 f0 44 6b 55 f8 00 44 29 d2 4c 63 ca 46 88 1c 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_KS_2147820498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.KS!MTB"
        threat_id = "2147820498"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b c0 4c 2b c8 b8 ?? ?? ?? ?? f7 eb 03 d3 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 8b c3 ff c3 6b d2 ?? 2b c2 48 63 c8 48 8b 05 ?? ?? ?? ?? 8a 14 01 43 32 14 01 41 88 10 49 ff c0 48 ff cf 75}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 8b c0 4c 2b c8 b8 ?? ?? ?? ?? f7 eb c1 fa ?? 8b c2 c1 e8 ?? 03 d0 8b c3 ff c3 8d 0c 92 c1 e1 ?? 2b c1 48 63 c8 48 8b 05 ?? ?? ?? ?? 8a 14 01 43 32 14 01 41 88 10 49 ff c0 48 ff cf 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotetcrypt_KT_2147821258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.KT!MTB"
        threat_id = "2147821258"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 eb c1 fa ?? 8b c2 c1 e8 ?? 03 d0 8b c3 ff c3 8d 0c 52 c1 e1 ?? 2b c1 48 63 c8 42 8a 04 09 43 32 04 02 41 88 00 49 ff c0 48 ff ce 74 ?? 4c 8b 0d ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 eb 03 d3 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 8b d3 ff c3 2b d0 4c 63 c2 48 8b 15 ?? ?? ?? ?? 45 8a 04 10 45 32 04 3f 44 88 07 48 ff c7 49 ff ce 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotetcrypt_KU_2147821401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.KU!MTB"
        threat_id = "2147821401"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 8d 40 01 f7 e7 8b cf 4d 8d 49 01 c1 ea ?? ff c7 6b c2 ?? 2b c8 48 63 c1 42 0f b6 0c 10 41 32 49 ff 41 88 48 ff 41 3b fb 7d 09 4c 8b 15 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = "#jgD%SAnSsFIqcyRymo^h*+##6QFR7otD%>kiT6PvZsglXygw%>cLuZ(1<@M*g" ascii //weight: 1
        $x_1_3 = "bdXZL(jCX24?n$ZvWmfYZmuhy>7?0Ff2I(L#?&hZ)RX>lO58WwLMRH$JR5%9oZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotetcrypt_KV_2147821567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.KV!MTB"
        threat_id = "2147821567"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 0c 01 b8 ?? ?? ?? ?? 42 32 4c 0f ?? 41 f7 e8 41 88 49 ?? c1 fa ?? 8b cb 8b c2 83 c3 ?? c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 8b 05 ?? ?? ?? ?? 83 c1 ?? 48 63 c9 0f b6 0c 01 42 32 4c 0e ?? 41 88 49 ?? 49 ff ca 74}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8d 7f 01 f7 eb c1 fa ?? 8b c2 c1 e8 ?? 03 d0 8b c3 ff c3 6b d2 ?? 2b c2 48 63 c8 48 8b 05 ?? ?? ?? ?? 0f b6 0c 01 41 32 4c 3e ff 88 4f ff 48 ff ce 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotetcrypt_KW_2147821612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.KW!MTB"
        threat_id = "2147821612"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 d8 49 f7 e6 48 89 de 48 29 d6 48 d1 ee 48 01 d6 48 c1 ee ?? 48 89 f0 48 c1 e0 ?? 48 29 c6 31 c9 31 d2 41 ff d7 48 03 35 ?? ?? ?? ?? 0f b6 04 33 42 32 04 23 88 04 1f 48 83 c3 ?? 48 81 fb ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b cb f7 eb 03 d3 ff c3 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 42 8a 0c 08 43 32 0c 02 41 88 08 49 ff c0 48 ff ce 74 ?? 4c 8b 0d ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotetcrypt_KX_2147821623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.KX!MTB"
        threat_id = "2147821623"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 f0 49 f7 e6 48 c1 ea ?? 48 89 d3 48 c1 e3 ?? 48 01 d3 31 c9 31 d2 41 ff d7 48 8b 05 ?? ?? ?? ?? 48 29 d8 0f b6 04 06 42 32 04 26 88 04 37 48 83 c6 01 48 81 fe ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 33 c9 ff 15 ?? ?? ?? ?? 8b c7 25 ?? ?? ?? ?? 7d ?? ff c8 83 c8 ?? ff c0 48 63 c8 48 8b 05 ?? ?? ?? ?? 0f b6 0c 01 32 0c 2b 88 0b ff c7 48 ff c3 48 83 ee 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotetcrypt_KY_2147821819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.KY!MTB"
        threat_id = "2147821819"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 eb c1 fa ?? 8b c2 c1 e8 ?? 03 d0 8b c3 ff c3 8d 0c 92 c1 e1 ?? 2b c1 48 63 c8 48 8b 05 ?? ?? ?? ?? 0f b6 0c 01 41 32 4c 3e ?? 88 4f ?? 48 ff ce 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_KZ_2147821854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.KZ!MTB"
        threat_id = "2147821854"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 eb 8b cb ff c3 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 8b 05 ?? ?? ?? ?? 48 63 d1 0f b6 0c 02 32 4c 2f ff 88 4f ff 48 83 ee 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_LA_2147823174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.LA!MTB"
        threat_id = "2147823174"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cb 48 8d 7f ?? f7 eb 03 d3 ff c3 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 8b 05 ?? ?? ?? ?? 48 63 d1 0f b6 0c 02 41 32 4c 3e ff 88 4f ff 48 ff ce 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_LB_2147823629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.LB!MTB"
        threat_id = "2147823629"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 20 99 b9 ?? ?? ?? ?? f7 f9 8b c2 48 98 48 8b 0d ?? ?? ?? ?? 0f b6 04 01 8b 4c 24 38 33 c8 8b c1 8b 4c 24 24 0f af 4c 24 24 8b 54 24 20 03 d1 8b ca 48 63 c9 48 8b 54 24 40 88 04 0a e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_LC_2147823801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.LC!MTB"
        threat_id = "2147823801"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 f7 e8 88 4f ?? c1 fa ?? 8b c2 c1 e8 ?? 03 d0 8b c6 83 c6 ?? 6b d2 ?? 2b c2 83 c0 ?? 48 63 c8 48 8b 05 ?? ?? ?? ?? 0f b6 0c 01 32 4c 3b ?? 49 ff cc 88 4f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_LD_2147823815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.LD!MTB"
        threat_id = "2147823815"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 eb 03 d3 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 8b d3 ff c3 2b d0 48 8b 05 ?? ?? ?? ?? 4c 63 c2 41 8a 14 00 42 32 14 37 88 17 48 ff c7 49 ff cf 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_LE_2147823845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.LE!MTB"
        threat_id = "2147823845"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 84 04 ?? ?? ?? ?? 89 44 24 ?? 48 8b 0d ?? ?? ?? ?? 8b 44 24 ?? 41 b8 ?? ?? ?? ?? 99 41 f7 f8 8b 44 24 ?? 48 63 d2 0f b6 0c 11 31 c8 88 c2 48 8b 44 24 ?? 48 63 4c 24 ?? 88 14 08 8b 44 24 ?? 83 c0 ?? 89 44 24 ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_LF_2147823970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.LF!MTB"
        threat_id = "2147823970"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 ff c2 f7 ee c1 fa ?? 8b c2 c1 e8 ?? 03 d0 8b c6 ff c6 6b d2 ?? 2b c2 48 63 c8 42 0f b6 04 01 43 32 44 11 ?? 48 ff cf 41 88 42 ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_LG_2147824194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.LG!MTB"
        threat_id = "2147824194"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 84 04 ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 99 b9 ?? ?? ?? ?? f7 f9 8b c2 48 98 48 8b 0d ?? ?? ?? ?? 0f b6 04 01 8b 4c 24 ?? 33 c8 8b c1 48 63 4c 24 ?? 48 8b 54 24 ?? 88 04 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_LH_2147824206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.LH!MTB"
        threat_id = "2147824206"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b cb 41 f7 eb 41 03 d3 41 ff c3 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 42 8a 0c 08 43 32 0c 10 41 88 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_LI_2147824277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.LI!MTB"
        threat_id = "2147824277"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 eb 8b cb ff c3 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 42 0f b6 0c 00 43 32 4c 0a ff 41 88 49}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_LJ_2147824397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.LJ!MTB"
        threat_id = "2147824397"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c8 f7 ea 8d 04 0a c1 f8 ?? 89 c2 89 c8 c1 f8 ?? 29 c2 89 d0 c1 e0 ?? 8d 14 c5 [0-4] 29 c2 89 c8 29 d0 48 98 4c 01 d0 0f b6 00 44 31 c8 41 88 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_LK_2147824411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.LK!MTB"
        threat_id = "2147824411"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 eb 03 d3 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 8b d3 ff c3 2b d0 48 8b 05 ?? ?? ?? ?? 4c 63 c2 41 8a 14 00 41 32 14 3f 88 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_LL_2147824458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.LL!MTB"
        threat_id = "2147824458"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 ef c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b d2 ?? 8b c7 2b c2 48 63 c8 48 8b 05 ?? ?? ?? ?? 0f b6 0c 01 32 0c 1e 88 0b}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 ee c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 8b d6 ff c6 2b d0 48 8b 05 ?? ?? ?? ?? 4c 63 c2 41 8a 14 00 41 32 14 1f 88 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Emotetcrypt_LM_2147824679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.LM!MTB"
        threat_id = "2147824679"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 c1 e8 ?? 03 d0 48 8b 05 ?? ?? ?? ?? 48 63 ca 48 63 d6 83 c6 ?? 48 6b c9 ?? 48 03 c8 0f b6 04 0a 32 44 2b ff 49 83 ec 01 88 45 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_LN_2147824684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.LN!MTB"
        threat_id = "2147824684"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 eb 2b d3 83 c3 ?? c1 fa ?? 8b c2 c1 e8 ?? 03 d0 48 8b 05 ?? ?? ?? ?? 48 63 d2 48 6b d2 ?? 48 03 d0 41 8a 04 10 41 32 04 3c 88 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_LO_2147824690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.LO!MTB"
        threat_id = "2147824690"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 c1 e8 ?? 03 d0 6b d2 ?? 41 8b c5 2b c2 48 63 c8 48 8b 05 ?? ?? ?? ?? 0f b6 0c 01 32 0c 33 88 0e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_LP_2147824830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.LP!MTB"
        threat_id = "2147824830"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 04 ?? 89 84 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 99 b9 ?? ?? ?? ?? f7 f9 8b c2 48 98 48 8b 0d ?? ?? ?? ?? 0f b6 04 01 8b 8c 24 ?? ?? ?? ?? 33 c8 8b c1 8b 8c 24 ?? ?? ?? ?? 8b 94 24 ?? ?? ?? ?? 03 d1 8b ca 2b 8c 24 ?? ?? ?? ?? 48 63 c9 48 8b 94 24 ?? ?? ?? ?? 88 04 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_LQ_2147824831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.LQ!MTB"
        threat_id = "2147824831"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 eb 03 d3 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 8b cb 2b c8 48 63 d1 48 8b 05 ?? ?? ?? ?? 0f b6 0c 02 32 0c 3e 88 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_LR_2147824832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.LR!MTB"
        threat_id = "2147824832"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 ef c1 fa ?? 8b c2 c1 e8 ?? 03 d0 48 8b 05 ?? ?? ?? ?? 48 63 ca 48 63 d7 83 c7 01 48 6b c9 ?? 48 03 c8 0f b6 04 0a 32 44 2b ff 49 83 ec 01 88 45 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_LS_2147824833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.LS!MTB"
        threat_id = "2147824833"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 ef c1 fa ?? 8b c2 c1 e8 ?? 03 d0 8d 0c d2 03 c9 8b c7 2b c1 48 63 c8 48 8b 05 ?? ?? ?? ?? 0f b6 0c 01 32 0c 1e 88 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_LT_2147825032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.LT!MTB"
        threat_id = "2147825032"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 98 0f b6 84 04 80 00 00 00 89 44 24 48 8b 44 24 20 99 b9 ?? ?? ?? ?? f7 f9 8b c2 48 98 48 8b 0d ?? ?? ?? ?? 0f b6 04 01 8b 4c 24 48 33 c8 8b c1 8b 0d ?? ?? ?? ?? 0f af 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_LU_2147825033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.LU!MTB"
        threat_id = "2147825033"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 c1 e8 1f 03 d0 41 8b c4 41 ff c4 6b d2 ?? 2b c2 42 8a 54 04 40 48 98 42 32 14 30 49 8b 06 00 41 ?? ?? c1 fa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_LV_2147825081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.LV!MTB"
        threat_id = "2147825081"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 f7 ee 41 03 d6 41 ff c6 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 42 8a 54 04 ?? 2b c8 48 63 c1 49 8b ca 42 32 14 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_LW_2147825082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.LW!MTB"
        threat_id = "2147825082"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 98 0f b6 84 04 ?? ?? ?? ?? 89 44 24 28 48 8b 0d ?? ?? ?? ?? 8b 44 24 30 41 b8 ?? ?? ?? ?? 99 41 f7 f8 8b 44 24 28 48 63 d2 0f b6 0c 11 31 c8 88 c2 48 8b 84 24 98 00 00 00 8b 4c 24 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_LX_2147825202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.LX!MTB"
        threat_id = "2147825202"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 f7 ee c1 fa ?? 8b c2 c1 e8 ?? 03 d0 41 8b c6 41 ff c6 8d 0c 92 c1 e1 ?? 2b c1 49 8b ca 48 98 46 32 0c 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_LY_2147825203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.LY!MTB"
        threat_id = "2147825203"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 f7 ef c1 fa ?? 8b c2 c1 e8 ?? 03 d0 41 8b c7 41 ff c7 8d 0c d2 48 8d 14 76 03 c9 2b c1 b9 ?? ?? ?? ?? 48 98 46 32 0c 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_LZ_2147825214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.LZ!MTB"
        threat_id = "2147825214"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 98 0f b6 44 04 50 89 84 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 99 83 e2 0f 03 c2 83 e0 0f 2b c2 48 98 48 8b 0d ?? ?? ?? ?? 0f b6 04 01 8b 8c 24 ?? ?? ?? ?? 33 c8 8b c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_MA_2147825404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.MA!MTB"
        threat_id = "2147825404"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 98 0f b6 44 04 [0-4] 89 84 24 [0-4] 8b 84 24 [0-4] 99 b9 ?? ?? ?? ?? f7 f9 8b c2 48 98 48 8b 0d ?? ?? ?? ?? 0f b6 04 01 8b 8c 24 [0-4] 33 c8 8b c1 8b 0d ?? ?? ?? ?? 8b 94 24 [0-4] 2b d1 8b ca 03 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_MB_2147825405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.MB!MTB"
        threat_id = "2147825405"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 98 0f b6 84 04 [0-4] 89 44 24 [0-4] 8b 44 24 [0-4] 99 b9 ?? ?? ?? ?? f7 f9 8b c2 48 98 48 8b 0d ?? ?? ?? ?? 0f b6 04 01 8b 4c 24 [0-4] 33 c8 8b c1 8b 0d ?? ?? ?? ?? 8b 54 24 [0-5] d1 8b ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_MC_2147826303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.MC!MTB"
        threat_id = "2147826303"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 f7 ee c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 42 8a 54 04 30 2b c8 48 63 c1 42 32 14 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_NM_2147826379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.NM!MTB"
        threat_id = "2147826379"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 0f af c3 48 03 c5 44 32 44 04 30 49 8b c1 48 0f af c3 48 2b d0 49 8d 42 ?? 48 83 c2 ?? 49 0f af c3 49 0f af d1 48 2b d0 49 63 c5 48 0f af c8 48 8d 04 2a 48 ff c5 48 03 c8 48 03 cb 48 03 cf 46 88 04 39}  //weight: 1, accuracy: Low
        $x_1_2 = "zo#I>#fBN9T@2jb3@IEinV2tzpBRgY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_MD_2147842321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.MD!MTB"
        threat_id = "2147842321"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 f9 48 69 f7 ?? ?? ?? ?? 48 89 f2 48 c1 ea ?? 48 c1 fe ?? 01 d6 6b d6 ?? 29 d7 48 63 d7 42 0f b6 14 02 32 14 0b 88 14 08 48 ff c1 8b 95 ?? ?? ?? ?? 48 39 d1 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_ME_2147842370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.ME!MTB"
        threat_id = "2147842370"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 89 c8 99 44 8b 4d ?? 41 f7 f9 4c 63 d2 42 0f b6 14 11 41 31 d0 45 88 c3 48 8b 8d ?? ?? ?? ?? 4c 63 55 ?? 46 88 1c 11 8b 45 ?? 83 c0 ?? 89 45 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emotetcrypt_MF_2147842601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emotetcrypt.MF!MTB"
        threat_id = "2147842601"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 01 89 84 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 99 [0-15] 48 98 48 8b 8c 24 ?? ?? ?? ?? 0f b6 04 01 8b 8c 24 ?? ?? ?? ?? 33 c8 8b c1 48 63 8c 24 ?? ?? ?? ?? 48 8b 94 24 ?? ?? ?? ?? 88 04 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

