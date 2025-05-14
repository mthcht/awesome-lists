rule Trojan_Win32_DllInject_Q_2147794854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.Q!MTB"
        threat_id = "2147794854"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {88 45 ff 0f b6 4d ff c1 f9 06 0f b6 55 ff c1 e2 02 0b ca 88 4d ff 0f b6 45 ff 83 e8 27 88 45 ff 0f b6 4d ff 81 f1 ca 00 00 00 88 4d ff}  //weight: 10, accuracy: High
        $x_3_2 = "mcdedxxdiu" ascii //weight: 3
        $x_3_3 = "RevokeBindStatusCallback" ascii //weight: 3
        $x_3_4 = "UrlMkGetSessionOption" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_EB_2147813137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.EB!MTB"
        threat_id = "2147813137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "CommandLineToArgvW" ascii //weight: 3
        $x_3_2 = "--process-name" ascii //weight: 3
        $x_3_3 = "--dump-block" ascii //weight: 3
        $x_3_4 = "DLL to inject" ascii //weight: 3
        $x_3_5 = "CreateRemoteThread injection" ascii //weight: 3
        $x_3_6 = "QueueUserAPC injection" ascii //weight: 3
        $x_3_7 = "inject error" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_UL_2147832883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.UL!MTB"
        threat_id = "2147832883"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a d9 2a da 80 e3 ed 32 19 32 d8 88 19 03 4d f8 3b ce}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_A_2147833578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.A!MTB"
        threat_id = "2147833578"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 03 45 f4 0f b6 08 8b 45 f4 99 be 1c 00 00 00 f7 fe 8b 45 fc 0f b6 14 10 33 ca 8b 45 f8 03 45 f4 88 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_A_2147833578_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.A!MTB"
        threat_id = "2147833578"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {15 10 ff 15 00 ?? 11 10 6a 00 6a 00 6a 01 68 ?? ?? 15 10 ff 15 04 ?? 11 10 c7 05 ?? ?? 15 10 0c 00 00 00 c7 05}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_MW_2147833805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.MW!MTB"
        threat_id = "2147833805"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 88 4d bd 33 d2 88 55 bc 33 c0 88 45 bb 8a 4d bd 88 4d a4 8a 55 bc 88 55 a0 8a 45 bb 88 45 9c b9 ?? ?? ?? ?? c7 85 18 ff ff ff ?? ?? ?? ?? 89 8d 1c ff ff ff 8b 95 18 ff ff ff 8b 85}  //weight: 1, accuracy: Low
        $x_1_2 = {0f 28 45 d0 0f 29 85 a0 fe ff ff 8b 4d 8c 0f 10 01 0f 29 85 b0 fe ff ff 0f 28 85 b0 fe ff ff 66 0f ef 85 a0 fe ff ff 0f 29 85 90 fe ff ff 0f 28 85 90 fe ff ff 8b 55 8c 0f 11 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_MA_2147835825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.MA!MTB"
        threat_id = "2147835825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "OnePro" ascii //weight: 3
        $x_3_2 = "TwoPro" ascii //weight: 3
        $x_3_3 = "ThrPro" ascii //weight: 3
        $x_3_4 = "estate.dll" ascii //weight: 3
        $x_1_5 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_MA_2147835825_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.MA!MTB"
        threat_id = "2147835825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 56 d8 e7 d8 d8 d8 c9 d8 e2 d8 ed 8a 0a d8 cd d8 c1 8a 0e d8 c3 d8 df d8 e6 8a 12 d8 cd d8 c2 d8 c8 d8 e1 d8 df d8 ea d8 e2 d8 d1 d8 ce d8 e1}  //weight: 1, accuracy: High
        $x_1_2 = {d8 da d8 c7 d8 c4 8a 13 eb 42 d8 cf d8 c8 d8 c6 d8 c5 d8 e7 d8 dd d8 d1 d8 eb d8 c8 88 0c d8 e6 d8 c8 89 11 d8 c6 d8 d1 d8 dc 88 0f d8 cb d8 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_MB_2147836281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.MB!MTB"
        threat_id = "2147836281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "TftvgEdrtcf" ascii //weight: 2
        $x_2_2 = "InffbTvfcrfg" ascii //weight: 2
        $x_2_3 = "PkmjnLminu" ascii //weight: 2
        $x_1_4 = "WaitForSingleObjectEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_MB_2147836281_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.MB!MTB"
        threat_id = "2147836281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {71 77 65 72 2e 64 6c 6c 00 4f 6e 65 46 00 54 77 6f 46 00 54 68 72 46}  //weight: 10, accuracy: High
        $x_3_2 = "OneF" ascii //weight: 3
        $x_3_3 = "TwoF" ascii //weight: 3
        $x_3_4 = "ThrF" ascii //weight: 3
        $x_3_5 = "qwer.dll" ascii //weight: 3
        $x_1_6 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_MB_2147836281_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.MB!MTB"
        threat_id = "2147836281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 0a d8 e9 d8 e1 d8 ec d8 df 89 11 eb 10 d8 d3 d8 c3 d8 cf 88 0e d8 d1 d8 ce d8 d9 89 0e eb 6a d8 d9 d8 e6 d8 e3 d8 d4 d8 d5 d8 db 8a 0b d8 e0}  //weight: 1, accuracy: High
        $x_1_2 = {89 0b d8 dd d8 cb d8 c5 89 10 d8 df d8 cf d8 e7 d8 d3 d8 dc d8 e2 d8 c1 d8 db d8 d9 d8 df 89 0a d8 d7 d8 d2 d8 e1 d8 eb d8 cb d8 d3 d8 ce d8 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_BJ_2147836586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.BJ!MTB"
        threat_id = "2147836586"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "OneNoPro" ascii //weight: 2
        $x_2_2 = "TwoNoPro" ascii //weight: 2
        $x_2_3 = "ThrNoPro" ascii //weight: 2
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_CB_2147837278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.CB!MTB"
        threat_id = "2147837278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "One1Neo" ascii //weight: 3
        $x_3_2 = "Two2Neo" ascii //weight: 3
        $x_3_3 = "Thr3Neo" ascii //weight: 3
        $x_3_4 = "rthryjt.dll" ascii //weight: 3
        $x_1_5 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_CB_2147837278_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.CB!MTB"
        threat_id = "2147837278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Bosejfgopseiopgesrj" ascii //weight: 2
        $x_2_2 = "Noaseiofsegoisegjes" ascii //weight: 2
        $x_2_3 = "OmsdgosjAopdfjhirjh" ascii //weight: 2
        $x_2_4 = "Oopiaeoigfsejgesa" ascii //weight: 2
        $x_1_5 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_GBQ_2147837398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.GBQ!MTB"
        threat_id = "2147837398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "One1Neo" ascii //weight: 2
        $x_2_2 = "Two2Neo" ascii //weight: 2
        $x_2_3 = "Thr3Neo" ascii //weight: 2
        $x_2_4 = "One8Neo" ascii //weight: 2
        $x_2_5 = "Two8Neo" ascii //weight: 2
        $x_2_6 = "Thr8Neo" ascii //weight: 2
        $x_2_7 = "rthryjt.dll" ascii //weight: 2
        $x_2_8 = "WaitForSingleObject" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_DllInject_BK_2147837644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.BK!MTB"
        threat_id = "2147837644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "RtcyvYvghb" ascii //weight: 2
        $x_2_2 = "EdtcfKhbgv" ascii //weight: 2
        $x_2_3 = "IhbgRvg" ascii //weight: 2
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_BL_2147838366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.BL!MTB"
        threat_id = "2147838366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SsgdfKiuyt" ascii //weight: 2
        $x_2_2 = "DegrhfLgjfhdf" ascii //weight: 2
        $x_2_3 = "NrhtjyJkyjth" ascii //weight: 2
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_BM_2147838765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.BM!MTB"
        threat_id = "2147838765"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "KnjhOnihb" ascii //weight: 2
        $x_2_2 = "ObuBvys" ascii //weight: 2
        $x_2_3 = "OnjiMbhuv" ascii //weight: 2
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_BN_2147839097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.BN!MTB"
        threat_id = "2147839097"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SctfvygFcgh" ascii //weight: 2
        $x_2_2 = "RfvgbhSfcvgbh" ascii //weight: 2
        $x_2_3 = "ScfvgJuim" ascii //weight: 2
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_BO_2147839622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.BO!MTB"
        threat_id = "2147839622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "TcrOnb" ascii //weight: 2
        $x_2_2 = "PjnRcfvg" ascii //weight: 2
        $x_2_3 = "RvgbhThbj" ascii //weight: 2
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_CMP_2147841039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.CMP!MTB"
        threat_id = "2147841039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {46 8a 46 ff ?? 56 83 c4 ?? 32 02 88 07 47 ?? 89 c0 42 83 ec 04 c7 ?? ?? ?? ?? ?? ?? 83 c4 04 49 89 c0 85 c9 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_ADL_2147842667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.ADL!MTB"
        threat_id = "2147842667"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ad a6 a4 00 8b ?? ?? ?? ?? 70 70 00 69 5f 5a 00 5b 4e 46 00 55 45 3a 00 53 42 35 ?? ?? ?? ?? 00 50 3f 35 00 4f 41 34 00 50 42 34 00 51 43 35 ?? ?? ?? ?? 00 54 46 38 00 57 49 3b 00 5d 4e 42 00 60 53 47 00 64 56 4c 00 68 5d 55 00 6d 63 5b 00 71 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_SPQ_2147842718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.SPQ!MTB"
        threat_id = "2147842718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BosghosrdjAjsrjirhr" ascii //weight: 1
        $x_1_2 = "LoshgsrijAjosjhgie" ascii //weight: 1
        $x_1_3 = "NsjgosjAjosjghejhg" ascii //weight: 1
        $x_1_4 = "PsjogosrAjosjrhirsj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_SP_2147847412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.SP!MTB"
        threat_id = "2147847412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Jjaiefhaduigehhgdhd" ascii //weight: 1
        $x_1_2 = "kakfgjaeiogjdsij" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_BZ_2147847530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.BZ!MTB"
        threat_id = "2147847530"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Jiajoifjaegeaijgdj" ascii //weight: 3
        $x_3_2 = "Laiofgjaeoigeagh" ascii //weight: 3
        $x_1_3 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_BT_2147847537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.BT!MTB"
        threat_id = "2147847537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Cokgsoigjseoigjse" ascii //weight: 3
        $x_3_2 = "Hoisdgjfiosjgie" ascii //weight: 3
        $x_1_3 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_BU_2147847614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.BU!MTB"
        threat_id = "2147847614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "LosfgksodfgAosjgisjdgj" ascii //weight: 3
        $x_3_2 = "Jioaejgfi9aesjifgsj" ascii //weight: 3
        $x_1_3 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_BY_2147847711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.BY!MTB"
        threat_id = "2147847711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CJijasgoisdjgsdij" ascii //weight: 2
        $x_2_2 = "Doiasdofiasdifoadsj" ascii //weight: 2
        $x_2_3 = "CjvboisdjYsoigjisoegjise" ascii //weight: 2
        $x_2_4 = "Coisgoiwegoiehgedifjd" ascii //weight: 2
        $x_5_5 = "WaitForSingleObject" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_DllInject_CA_2147847802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.CA!MTB"
        threat_id = "2147847802"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Fiosuooegfhdhfudu" ascii //weight: 2
        $x_2_2 = "Oisidashgsueghdh" ascii //weight: 2
        $x_2_3 = "Cioaoifajasifj" ascii //weight: 2
        $x_2_4 = "Koiasdgjiosdgiosdj" ascii //weight: 2
        $x_5_5 = "WaitForSingleObject" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_DllInject_GR_2147848385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.GR!MTB"
        threat_id = "2147848385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 54 3d e8 8d 5d f0 88 55 f0 e8 3d 02 00 00 88 44 3d e8 47 83 ff 04 7c e7}  //weight: 1, accuracy: High
        $x_1_2 = "M2YxMGUyM2JiMWE1ZGZkOWM4Y2EwNjE5NWU0MzA0MzM4NmE5YmE0YzYzYzM1YWM1MThmNDYzYmE3NjhmMDAxYg==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_XZ_2147903389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.XZ!MTB"
        threat_id = "2147903389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 05 14 9b 4f 00 88 01 41 8a 01 84 c0 75 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_SUP_2147931946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.SUP!MTB"
        threat_id = "2147931946"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 ff 30 64 89 20 8b c3 e8 98 b8 fd ff 50 e8 52 69 fe ff 89 45 f8 33 c0 5a 59 59 64 89 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_NIT_2147932228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.NIT!MTB"
        threat_id = "2147932228"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DLL Injected!" ascii //weight: 2
        $x_2_2 = "PROCESS INJECTION" ascii //weight: 2
        $x_2_3 = "_Query_perf_counter" ascii //weight: 2
        $x_2_4 = "Process opened successfully" ascii //weight: 2
        $x_2_5 = "Release\\skeet2.pdb" ascii //weight: 2
        $x_1_6 = "terminate" ascii //weight: 1
        $x_1_7 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_8 = "WriteProcessMemory" ascii //weight: 1
        $x_1_9 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllInject_GVC_2147941418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllInject.GVC!MTB"
        threat_id = "2147941418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 1c a1 ?? ?? ?? ?? 33 c5 89 45 fc 89 4d e8 c7 45 e4 0f 00 00 00 c6 45 ec c3 c6 45 ed 7e c6 45 ee 3b c6 45 ef 8f c6 45 f0 2c c6 45 f1 17 c6 45 f2 52 c6 45 f3 0c c6 45 f4 ef c6 45 f5 6f c6 45 f6 3b c6 45 f7 9d c6 45 f8 2b c6 45 f9 33 c6 45 fa 02 a1 ?? ?? ?? ?? 64 8b 0d 2c 00 00 00 8b 14 81 8b 82 2c 00 00 00 83 e0 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

