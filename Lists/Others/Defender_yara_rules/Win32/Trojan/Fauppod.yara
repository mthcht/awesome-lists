rule Trojan_Win32_Fauppod_A_2147828150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.A"
        threat_id = "2147828150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {78 50 2b 3d 5f 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_2 = {66 c7 00 4d 5a [0-3] c7 ?? 3c c0 00 00 00 c7 ?? c0 00 00 00 50 45}  //weight: 1, accuracy: Low
        $x_1_3 = {e8 de ff ff ff 40 1a 00 89 18 89 f0 01 05 ?? ?? ?? ?? 89 ea 01 15}  //weight: 1, accuracy: Low
        $x_1_4 = {e8 df ff ff ff 40 2a 00 e8 ?? ?? ?? ?? 89 d8 a3 ?? ?? ?? ?? 89 f0 31 05 ?? ?? ?? ?? 89 ea 01 15}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 30 8b 78 04 8b 58 08 8b 68 0c 8b 60 10 8b 40 14 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Fauppod_D_2147828237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.D"
        threat_id = "2147828237"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 64 50 66 78 4d 61 51 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_2 = {66 c7 00 4d 5a [0-3] c7 ?? 3c c0 00 00 00 c7 ?? c0 00 00 00 50 45}  //weight: 1, accuracy: Low
        $x_1_3 = {e8 18 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ff d0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? e2 c8}  //weight: 1, accuracy: Low
        $x_1_4 = {8a 45 14 8b 4d 10 8b 55 0c 8b 75 08 [0-2] 8a 24 0a 28 c4 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Fauppod_F_2147828405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.F"
        threat_id = "2147828405"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 c7 00 4d 5a [0-3] c7 ?? 3c c0 00 00 00 c7 ?? c0 00 00 00 50 45}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 00 c0 00 00 00 [0-3] c7 ?? c0 00 00 00 50 45}  //weight: 1, accuracy: Low
        $x_1_3 = {e8 05 00 00 00 e8 ?? ?? ff ff 8d 05 ?? ?? ?? ?? 89 18 89 f0 01 05 [0-26] (eb|e2) [0-3] 89 45 00 90}  //weight: 1, accuracy: Low
        $x_1_4 = {e8 18 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ff d0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? e2 c8}  //weight: 1, accuracy: Low
        $x_1_5 = {8a 45 14 8b 4d 10 8b 55 0c 8b 75 08 [0-2] 8a 24 0a 28 c4 88}  //weight: 1, accuracy: Low
        $x_1_6 = {e8 df ff ff ff 40 2a 00 e8 ?? ?? ?? ?? 89 d8 a3 ?? ?? ?? ?? 89 f0 31 05 ?? ?? ?? ?? 89 ea 01 15}  //weight: 1, accuracy: Low
        $x_1_7 = {e8 de ff ff ff 40 1a 00 89 18 89 f0 01 05 ?? ?? ?? ?? 89 ea 01 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Fauppod_B_2147838865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.B!MTB"
        threat_id = "2147838865"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "OneNeo" ascii //weight: 2
        $x_2_2 = "TwoNeo" ascii //weight: 2
        $x_2_3 = "ThrNeo" ascii //weight: 2
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_MA_2147839058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.MA!MTB"
        threat_id = "2147839058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "RfghGvygubh" ascii //weight: 2
        $x_2_2 = "LjnhDdctfvg" ascii //weight: 2
        $x_2_3 = "YtbFftvyg" ascii //weight: 2
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_MA_2147839058_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.MA!MTB"
        threat_id = "2147839058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 de ff ff ff 40 2a 00 e8 ?? ?? ff ff 8d 05 ?? ?? ?? ?? 89 18 89 f0 01 05 ?? ?? ?? ?? 89 ea 01 15}  //weight: 1, accuracy: Low
        $x_1_2 = {89 45 00 55 89 e5 83 e4 f8 83 ec 70 31 c0 89 44 24 60 8b 44 24 60}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 e8 8b 4d f0 8a 14 01 8b 75 ec 88 14 06 05 01 00 00 00 8b 7d f4 39 f8 89 45 e8 75 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_MB_2147839059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.MB!MTB"
        threat_id = "2147839059"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DdctfvHubhnj" ascii //weight: 2
        $x_2_2 = "OjnhTfcd" ascii //weight: 2
        $x_2_3 = "EfvhPjnhjb" ascii //weight: 2
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_MC_2147839229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.MC!MTB"
        threat_id = "2147839229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "JbyvtFrctv" ascii //weight: 2
        $x_2_2 = "LunbySrdft" ascii //weight: 2
        $x_2_3 = "EtvOnhb" ascii //weight: 2
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_MD_2147839324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.MD!MTB"
        threat_id = "2147839324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "YfcvygFftvyg" ascii //weight: 2
        $x_2_2 = "YvygbhJhbug" ascii //weight: 2
        $x_2_3 = "OunTvfg" ascii //weight: 2
        $x_1_4 = "WaitForSingleObjectEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_ME_2147839920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.ME!MTB"
        threat_id = "2147839920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "TercvOimnuy" ascii //weight: 2
        $x_2_2 = "TrctvybKunby" ascii //weight: 2
        $x_2_3 = "OnubyvDtcvyb" ascii //weight: 2
        $x_1_4 = "WaitForSingleObjectEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_MF_2147840350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.MF!MTB"
        threat_id = "2147840350"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "OneNdoPro" ascii //weight: 2
        $x_2_2 = "TwoNdoPro" ascii //weight: 2
        $x_2_3 = "ThrNdoPro" ascii //weight: 2
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_MG_2147840351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.MG!MTB"
        threat_id = "2147840351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "UbycomiTrgyb" ascii //weight: 2
        $x_2_2 = "PnubyEcfvgbh" ascii //weight: 2
        $x_2_3 = "PnuybDtvyb" ascii //weight: 2
        $x_1_4 = "WaitForSingleObjectEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_DA_2147845207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.DA!MTB"
        threat_id = "2147845207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 06 46 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 51 83 c4 04 32 02 ?? 88 07 47 ?? 68 ?? ?? ?? ?? 83 c4 04 83 c2 01 49 ?? 85 c9 75}  //weight: 10, accuracy: Low
        $x_10_2 = {8a 06 46 32 02 68 ?? ?? ?? ?? 83 c4 04 88 07 83 c7 01 89 c0 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 42 ?? 50 83 c4 04 49 [0-2] 85 c9 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Fauppod_MH_2147847713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.MH!MTB"
        threat_id = "2147847713"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 e5 83 ec 04 89 3c 24 51 83 c4 04 56 52 83 c4 04 89 4c 24 fc 83 ec 04 68 ?? ?? ?? ?? 83 c4 04 52 83 c4 04 8b 7d 08 53 83 c4 04 8b 75 0c 89 c0 8b 4d 10 85 c9 74}  //weight: 2, accuracy: Low
        $x_2_2 = {83 c4 04 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 8b 7d 0c 52 83 c4 04 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 57 5a 31 c0 66 8b 06 46 46 53 83 c4 04 50 83 c4 04 85 c0 74}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Fauppod_SPD_2147847759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.SPD!MTB"
        threat_id = "2147847759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "subduepRdeepthereall.kWfruitful5" ascii //weight: 1
        $x_1_2 = "sk4ItEstarsdominionaseasmidst" ascii //weight: 1
        $x_1_3 = "don.tCvgreaterAll" ascii //weight: 1
        $x_1_4 = "7letOnito" ascii //weight: 1
        $x_1_5 = "JIqWhereinmovethDaypvform" ascii //weight: 1
        $x_1_6 = "DCreepethcreepethX" ascii //weight: 1
        $x_1_7 = "creepethliving9air.5eq" ascii //weight: 1
        $x_1_8 = "BNwhaleshimhiswmaleCgreatS" ascii //weight: 1
        $x_1_9 = "b3GreaterkwOseaDhad" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_C_2147849483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.C!MTB"
        threat_id = "2147849483"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04}  //weight: 2, accuracy: Low
        $x_2_2 = {80 3a 00 74}  //weight: 2, accuracy: High
        $x_2_3 = "WdrctfPjnkhbg" ascii //weight: 2
        $x_2_4 = "MbihuyvtyDtrcyv" ascii //weight: 2
        $x_2_5 = "RcytvgHvubhm" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_MI_2147852163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.MI!MTB"
        threat_id = "2147852163"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "IbgvyfDtvy" ascii //weight: 3
        $x_3_2 = "IbyuDtvuyb" ascii //weight: 3
        $x_3_3 = "IybuEctfyvg" ascii //weight: 3
        $x_1_4 = "CloseHandle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GNQ_2147852303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GNQ!MTB"
        threat_id = "2147852303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {46 8a 46 ff 68 ?? ?? ?? ?? 83 c4 04 32 02 47 88 47 ff 89 c0 42 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 89 c0 83 e9 01 89 c0 ?? 85 c9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GNS_2147852321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GNS!MTB"
        threat_id = "2147852321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 83 c6 01 8a 46 ff 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 32 02 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 88 07 47}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GNS_2147852321_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GNS!MTB"
        threat_id = "2147852321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 68 ?? ?? ?? ?? 83 c4 04 32 02 83 ec 04 c7 04 ?? ?? ?? ?? 6f 83 c4 04 83 c7 01 88 47 ff ?? 83 c2 01 68 ?? ?? ?? ?? 83 c4 04 49 53 83 c4 04 89 c0 85 c9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GNT_2147852331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GNT!MTB"
        threat_id = "2147852331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 c8 88 45 ?? 8a 45 ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c0 83 c4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GNT_2147852331_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GNT!MTB"
        threat_id = "2147852331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 14 68 ?? ?? ?? ?? 83 c4 04 80 3a 00 ?? ?? ?? ?? ac 32 02 47 88 47 ff 68 ?? ?? ?? ?? 83 c4 04 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 42 83 e9 01 85 c9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GNT_2147852331_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GNT!MTB"
        threat_id = "2147852331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 83 c6 01 8a 46 ff ?? 32 02 ?? 47 88 47 ff}  //weight: 10, accuracy: Low
        $x_10_2 = {83 c4 04 42 89 c0 89 c0 83 e9 01 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 85 c9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_PA_2147853044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.PA!MTB"
        threat_id = "2147853044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 8a 06 83 c6 01 83 ec 04 c7 04 24 [0-4] 83 c4 04 83 ec 04 c7 04 24 [0-4] 83 c4 04 32 02 88 07 47 51 83 c4 04 42 83 ec 04 c7 04 24 [0-4] 83 c4 04 53 83 c4 04 49 85 c9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_PC_2147853381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.PC!MTB"
        threat_id = "2147853381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3a 00 74 [0-4] ac 32 02 88 07 47 51 83 c4 ?? 42 89 c0 56 83 c4 ?? 83 e9 ?? 89 c0 85 c9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_PB_2147853509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.PB!MTB"
        threat_id = "2147853509"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 8d 50 01 0f b7 ca 89 4c 24 ?? 8b 34 24 66 d1 c6 0f b7 fe 8b 5c 24 ?? 0f b7 14 5d ?? ?? ?? ?? 8d 87 ?? ?? ?? ?? 66 c1 c0 0b 0f b7 c8 33 d1 88 54 1c ?? 89 0c 24 84 d2 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_MJ_2147888118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.MJ!MTB"
        threat_id = "2147888118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 f2 68 88 54 24 68 8a 44 24 68 8a d0 02 c0 c0 ea 07 0a d0 8b 74 24 64 8a c2 04 f3 8a 9e ?? ?? ?? ?? 02 d8 88 5c 34 10 46 81 e6 ff 00 00 00 89 74 24 64 83 fe 4c 7c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_PD_2147888204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.PD!MTB"
        threat_id = "2147888204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3a 00 74 [0-6] 68 ?? ?? ?? ?? 83 c4 04 8a 06 46 53 83 c4 04 32 02 88 07 47 89 c0 83 c2 01 90 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 49 85 c9 75 ?? 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_PE_2147888275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.PE!MTB"
        threat_id = "2147888275"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3a 00 74 [0-6] 8a 06 46 32 02 83 c7 01 88 47 [0-4] 83 c2 01 53 83 c4 04 89 c0 83 e9 01 68 [0-4] 83 c4 04 89 c0 85 c9 75 ?? 61 c9 c2 10 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_PF_2147888299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.PF!MTB"
        threat_id = "2147888299"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3a 00 74 [0-6] 83 c6 01 8a 46 ?? 89 c0 32 02 88 07 47 56 83 c4 04 83 c2 01 49 51 83 c4 04 90 85 c9 75 ?? 61 c9 c2 10 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_PG_2147888867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.PG!MTB"
        threat_id = "2147888867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3a 00 74 [0-6] 8a 06 83 c6 01 89 c0 32 02 68 ?? ?? ?? ?? 83 c4 04 47 88 47 ?? 89 c0 90 83 c2 01 83 e9 01 51 83 c4 04 85 c9 75 ?? 61 c9 c2 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_MM_2147888896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.MM!MTB"
        threat_id = "2147888896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {eb 6a d8 d2 d8 e6 d8 df d8 d0 d8 c9 d8 cc d8 c1 89 0a d8 e8 d8 c4 d8 d7 d8 c0 d8 ed d8 d8 d8 c2 d8 e8 d8 c2 d8 cb 88 13 d8 cc d8 e8 d8 e9 d8 c5 d8 d6 d8 ed d8 e6 d8 d7 d8 e7 8a 0d d8 c1 d8 c0}  //weight: 5, accuracy: High
        $x_5_2 = {d8 ce d8 c6 d8 e2 d8 d0 d8 ed d8 ed d8 c4 88 0a d8 df d8 dd d8 c6 d8 cd 88 0d d8 e5 d8 e1 d8 c3 d8 e3 d8 d7 d8 d6 d8 d9 d8 d8 89 0e e9 84}  //weight: 5, accuracy: High
        $x_5_3 = {e9 8a 00 00 00 d8 de d8 dd d8 e8 d8 c5 d8 e7 d8 e4 d8 c6 d8 cb 88 0b d8 c5 d8 c5 d8 e4 d8 e4 d8 c6 d8 c4 89 0f d8 d5 d8 c0 d8 cc d8 cc d8 c2 d8 e3 d8 c7 d8 cd 89 0b d8 cf d8 d0 d8 d2 d8 d1 d8}  //weight: 5, accuracy: High
        $x_5_4 = {e0 d8 c7 d8 c3 d8 ed d8 d0 d8 d6 89 0c d8 e0 d8 da d8 ce d8 d8 d8 c6 d8 cb d8 cf d8 df d8 e0 d8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Fauppod_PH_2147888906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.PH!MTB"
        threat_id = "2147888906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3a 00 74 ?? 90 90 90 ac 89 c0 32 02 89 c0 aa 42 90 53 83 c4 04 49 56 83 c4 04 85 c9 75 ?? 61 c9 c2 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_PI_2147888907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.PI!MTB"
        threat_id = "2147888907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3a 00 74 ?? 90 90 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 8a 06 83 c6 01 90 32 02 56 83 c4 04 88 07 83 c7 01 56 83 c4 04 42 83 e9 01 89 c0 85 c9 75 ?? 61 c9 c2 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_PJ_2147889097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.PJ!MTB"
        threat_id = "2147889097"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3a 00 74 ?? 90 90 83 c6 01 8a 46 ?? 90 89 c0 32 02 89 c0 aa 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 42 68 [0-4] 83 c4 04 49 90 85 c9 75 ?? 61 c9 c2 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_PK_2147889098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.PK!MTB"
        threat_id = "2147889098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3a 00 74 ?? 90 90 ac 32 02 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 88 07 47 89 c0 83 c2 01 57 83 c4 04 83 e9 01 56 83 c4 04 85 c9 75 ?? 61 c9 c2 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_PL_2147889114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.PL!MTB"
        threat_id = "2147889114"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3a 00 74 ?? 90 90 8a 06 46 68 ?? ?? ?? ?? 83 c4 04 68 ?? ?? ?? ?? 83 c4 04 32 02 89 c0 83 c7 01 88 47 ?? 68 ?? ?? ?? ?? 83 c4 04 42 68 ?? ?? ?? ?? 83 c4 04 90 49 68 ?? ?? ?? ?? 83 c4 04 89 c0 85 c9 75 ?? 61 c9 c2 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_PM_2147889321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.PM!MTB"
        threat_id = "2147889321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3a 00 74 ?? 90 90 46 8a 46 ?? 51 83 c4 04 53 83 c4 04 32 02 88 07 83 c7 01 90 42 83 e9 01 85 c9 75 ?? 61 c9 c2 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_PN_2147889322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.PN!MTB"
        threat_id = "2147889322"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3a 00 74 [0-6] 83 c6 01 8a 46 ?? 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 32 02 aa 52 83 c4 04 89 c0 83 c2 01 68 ?? ?? ?? ?? 83 c4 04 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 49 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 85 c9 75 ?? 61 c9 c2 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_PO_2147889490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.PO!MTB"
        threat_id = "2147889490"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3a 00 74 [0-6] 8a 06 83 c6 01 51 83 c4 04 32 02 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 88 07 47 90 83 c2 01 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 49 56 83 c4 04 68 ?? ?? ?? ?? 83 c4 04 85 c9 75 ?? 61 c9 c2 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_PP_2147889491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.PP!MTB"
        threat_id = "2147889491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3a 00 74 ?? 90 90 46 8a 46 ?? 89 c0 32 02 89 c0 aa 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 42 83 e9 01 90 85 c9 75 ?? 61 c9 c2 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_MO_2147891556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.MO!MTB"
        threat_id = "2147891556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 04 46 8a 46 ff 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 68 ?? ?? ?? ?? 83 c4 04 32 02 89 c0 88 07 83 c7 01 57 83 c4 04 42 68 ?? ?? ?? ?? 83 c4 04 49}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_MP_2147892921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.MP!MTB"
        threat_id = "2147892921"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 04 32 02 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 88 07 83 c7 01 ?? 42 ?? 83 e9 01 85 c9 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_PQ_2147893052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.PQ!MTB"
        threat_id = "2147893052"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ac 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 68 ?? ?? ?? ?? 83 c4 04 32 02 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 83 c7 01 88 47 ?? 83 c2 01 49 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 68 ?? ?? ?? ?? 83 c4 04 85 c9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_PR_2147893145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.PR!MTB"
        threat_id = "2147893145"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3a 00 74 ?? 90 90 8a 06 46 90 51 83 c4 04 32 02 88 07 47 89 c0 42 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 49 68 ?? ?? ?? ?? 83 c4 04 85 c9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_MK_2147893160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.MK!MTB"
        threat_id = "2147893160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "OnePro" ascii //weight: 3
        $x_3_2 = "TwoPro" ascii //weight: 3
        $x_3_3 = "ThrPro" ascii //weight: 3
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_MQ_2147893805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.MQ!MTB"
        threat_id = "2147893805"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 06 83 c6 01 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 68 ?? ?? ?? ?? 83 c4 04 32 02 88 07 47 83 ec 04}  //weight: 5, accuracy: Low
        $x_5_2 = {83 c4 04 83 c2 01 68 ?? ?? ?? ?? 83 c4 04 68 ?? ?? ?? ?? 83 c4 04 49 [0-4] 85 c9 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_MR_2147894351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.MR!MTB"
        threat_id = "2147894351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RTCYVUYB.DLL" ascii //weight: 1
        $x_1_2 = "UjnhbjIgvbh" ascii //weight: 1
        $x_1_3 = "ActfvygRcy" ascii //weight: 1
        $x_1_4 = "EtcyvYvgbh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_IP_2147894366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.IP!MTB"
        threat_id = "2147894366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 8b 72 30 8b 76 0c 8b 76 0c ad 8b 30 8b 7e 18 8b 5f 3c 8b 5c 1f 78 8b 74 1f 20 01 fe}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_MKV_2147895254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.MKV!MTB"
        threat_id = "2147895254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 f2 89 55 e0 8b 55 e0 89 d0 99 f7 f9 89 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8b 55 dc 8b 75 ec 0f b6 14 16 8b 35 ?? ?? ?? ?? 8b 7d e4 0f b6 34 37 31 f2 88 d3 8b 55 dc 8b 75 e8 88 1c 16 8b 45 dc 05 01 00 00 00 89 45 dc e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GMB_2147896742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GMB!MTB"
        threat_id = "2147896742"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 38 4a 8d 05 ?? ?? ?? ?? 31 18 40 83 e8 03 31 35 ?? ?? ?? ?? 31 d0 29 c2 89 2d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GAN_2147899635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GAN!MTB"
        threat_id = "2147899635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {40 48 8d 05 ?? ?? ?? ?? 31 38 42 8d 05 ?? ?? ?? ?? 31 30 42 89 d0 89 e8 50 8f 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_AMAF_2147900899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.AMAF!MTB"
        threat_id = "2147900899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 0b 8b 55 e8 8b 75 d0 8a 2c 32 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 30 cd 8b 55 e4 88 2c 32 8b 55 f0 39 d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_AMBB_2147902309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.AMBB!MTB"
        threat_id = "2147902309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 89 e5 8a 45 0c 8a 4d 08 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 30 c8 0f b6 c0 5d c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_RX_2147904286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.RX!MTB"
        threat_id = "2147904286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 45 ff 88 4d fe 8a 45 ff 8a 4d fe 30 c8 0f b6 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_ZK_2147905389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.ZK!MTB"
        threat_id = "2147905389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 d1 81 e1 ff 00 00 00 89 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? e2 02 00 00 8a 0c 0b 8b 55 e8 8b 75 d4 32 0c 32 8b 55 e4 88 0c 32 c7 05 ?? ?? ?? ?? 0b 13 00 00 8b 4d f0 39 cf 89 7d cc 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_AFU_2147906177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.AFU!MTB"
        threat_id = "2147906177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nighttree.wRgivenupon3themmoveth0" ascii //weight: 1
        $x_1_2 = "FhLYou.llgreater4their" ascii //weight: 1
        $x_1_3 = "7ofirmamentorE" ascii //weight: 1
        $x_1_4 = "iisn.tisRhisxabovefourth" ascii //weight: 1
        $x_1_5 = "eartheveningso" ascii //weight: 1
        $x_1_6 = "fowl1Sgreatwatersrkfourth" ascii //weight: 1
        $x_1_7 = "2nFoZWas.is" ascii //weight: 1
        $x_1_8 = "gatheredgreatHsecondPlacemanblikenessC9" ascii //weight: 1
        $x_1_9 = "dnitnrwah44.dll" ascii //weight: 1
        $x_1_10 = "SjstAffduro" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_SPDB_2147907990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.SPDB!MTB"
        threat_id = "2147907990"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "OiaawtOtnkeleihlle" ascii //weight: 2
        $x_1_2 = "OiaawtOtnkeleihlle" ascii //weight: 1
        $x_1_3 = "ekrnn73.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_CO_2147908418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.CO!MTB"
        threat_id = "2147908418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 89 e5 50 8a 45 0c 8a 4d 08 30 c8}  //weight: 2, accuracy: High
        $x_2_2 = {0f b6 c0 83 c4 04 5d c3}  //weight: 2, accuracy: High
        $x_4_3 = {55 89 e5 8a 45 0c 8a 4d 08 30 c8 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 7e 0f 00 00 c7 05 ?? ?? ?? ?? 51 e9 ff ff 0f b6 c0 5d c3}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fauppod_AMMF_2147909499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.AMMF!MTB"
        threat_id = "2147909499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 55 fa 0f b6 75 fb 89 55 f4 89 75 f0 8b 45 f4 8b 4d f0 31 c8 88 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_SPZX_2147911219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.SPZX!MTB"
        threat_id = "2147911219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "JeehPeeaeor" ascii //weight: 2
        $x_2_2 = "JeehPeeaeor" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GXT_2147911670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GXT!MTB"
        threat_id = "2147911670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {40 01 d0 4a 42 01 25 ?? ?? ?? ?? 01 d0 83 c2 ?? 48 ?? ?? 4a 8d 05 ?? ?? ?? ?? 89 18 83 c0 ?? 01 3d ?? ?? ?? ?? 83 f2 ?? 89 d0 8d 05 ?? ?? ?? ?? 31 28 31 35}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_SPUO_2147911958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.SPUO!MTB"
        threat_id = "2147911958"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "IhzpheuldS" ascii //weight: 2
        $x_2_2 = "IhzpheuldS" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_AMMI_2147912120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.AMMI!MTB"
        threat_id = "2147912120"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 8a 45 ?? 8a 4d ?? 8b 15 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c0 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GXU_2147912350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GXU!MTB"
        threat_id = "2147912350"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 20 83 c2 ?? 83 c2 ?? ?? ?? 8d 05 ?? ?? ?? ?? 89 30 31 3d ?? ?? ?? ?? 83 c2 ?? 89 d0 ba ?? ?? ?? ?? 89 e8 50 8f 05 ?? ?? ?? ?? 40 89 d8 50}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GYA_2147912814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GYA!MTB"
        threat_id = "2147912814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 20 4a b8 ?? ?? ?? ?? 48 eb ?? 89 f0 50 8f 05 ?? ?? ?? ?? 31 d0 8d 05 ?? ?? ?? ?? 31 28 89 d0 89 d8 50}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GNK_2147913054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GNK!MTB"
        threat_id = "2147913054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? 89 d6 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 81 c2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_SPVX_2147913230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.SPVX!MTB"
        threat_id = "2147913230"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "EteiawnHqiteatilpnii" ascii //weight: 2
        $x_2_2 = "EteiawnHqiteatilpnii" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GXZ_2147913360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GXZ!MTB"
        threat_id = "2147913360"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 8a 45 0c 8a 4d 08 30 c8 8b 15 ?? ?? ?? ?? a2 ?? ?? ?? ?? 89 d6 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_ASGL_2147913581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.ASGL!MTB"
        threat_id = "2147913581"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 89 e5 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? 10 81 c2 ?? ?? ?? 00 89 15 ?? ?? ?? 10 30 c8 a2}  //weight: 5, accuracy: Low
        $x_5_2 = {55 89 e5 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? 10 81 c2 ?? ?? ?? ff 89 15 ?? ?? ?? 10 30 c8 a2 ?? ?? ?? 10 0f b6 c0 5d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Fauppod_GNX_2147913844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GNX!MTB"
        threat_id = "2147913844"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 4d 08 30 c8 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GNX_2147913844_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GNX!MTB"
        threat_id = "2147913844"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e5 8a 45 ?? 8a 4d ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GNX_2147913844_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GNX!MTB"
        threat_id = "2147913844"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 89 e5 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? a8 06 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = {55 89 e5 8a 45 0c 8a 4d 08 30 c8 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? a8 06 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Fauppod_GNV_2147914036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GNV!MTB"
        threat_id = "2147914036"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 45 ff 88 4d fe 8a 45 ff 8a 4d fe 30 c8 a2 60 7f 5b 00 c7 05 ?? ?? ?? ?? a8 06 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GNU_2147914102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GNU!MTB"
        threat_id = "2147914102"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e5 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 30 c8 c7 05 ?? ?? ?? ?? a8 06 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_SCPP_2147914939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.SCPP!MTB"
        threat_id = "2147914939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "RastladrtCeyntb" ascii //weight: 2
        $x_1_2 = "keevel85.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_AMAJ_2147915051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.AMAJ!MTB"
        threat_id = "2147915051"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 8a 45 0c 8a 4d 08 30 c8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c0 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_N_2147915814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.N"
        threat_id = "2147915814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {78 77 6e 7a 72 73 77 6f 34 32 2e 64 6c 6c 00 52 6c 6f 73 72 65 65 6e 68 61 48 00 6b 65 72 6e 65 6c 33 32 2e 53 65 74 54 68 72 65 61 64 50 72 69 6f 72 69 74 79 42 6f 6f 73 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GZM_2147916038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GZM!MTB"
        threat_id = "2147916038"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e5 8a 45 ?? 8a 4d ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GNM_2147916623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GNM!MTB"
        threat_id = "2147916623"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 c2 02 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 30 c8 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GNM_2147916623_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GNM!MTB"
        threat_id = "2147916623"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 c8 8b 55 ?? 0f af d1 88 d4 88 25 ?? ?? ?? ?? 8a 65 ?? 88 25 ?? ?? ?? ?? 8a 65 ?? 88 25 ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? 31 d1 88 cc 88 25 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 4e 0a 00 00 0f b6 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_SSZC_2147916787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.SSZC!MTB"
        threat_id = "2147916787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 45 fa a2 ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? 0f b6 35 ?? ?? ?? ?? 89 55 f4 89 75 f0 8b 45 f4 8b 4d f0 31 c8 88 c2 88 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2d e0 0e 00 00 a3 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 4e 0a 00 00 0f b6 05 ?? ?? ?? ?? 83 c4 0c 5e}  //weight: 2, accuracy: Low
        $x_1_2 = "EesIwysullstetwlssi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_SZZC_2147917013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.SZZC!MTB"
        threat_id = "2147917013"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e5 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? 81 c2 4e 09 00 00 89 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 22 04 00 00 0f b6 c0 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_SXZC_2147917961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.SXZC!MTB"
        threat_id = "2147917961"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8a 45 fa a2 ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? 0f b6 35 ?? ?? ?? ?? 31 f2 88 d0 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 83 c4 04 5e}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_SXXC_2147918313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.SXXC!MTB"
        threat_id = "2147918313"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8a 45 0c 8a 4d 08 88 0d ?? ?? ?? ?? 88 c2 30 ca a2 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c2 5d}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_SBXC_2147918331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.SBXC!MTB"
        threat_id = "2147918331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 45 0c 8a 4d 08 88 c2 02 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c0 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_MEA_2147918455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.MEA!MTB"
        threat_id = "2147918455"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {89 d3 01 fb 8b 3b 69 d8 e8 00 00 00 01 da 81 c2 0a 00 00 00 0f b7 12 31 f2 8b b5 98 fe ff ff 01 ce 89 34 24 89 7c 24 04}  //weight: 3, accuracy: High
        $x_3_2 = {8b 45 e0 8b 4d e4 03 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 4d f0 8a 14 01 8b 75 ec 88 14 06 05 01 00 00 00 8b 7d f4 39 f8 89 45 dc 74}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_SKXC_2147918529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.SKXC!MTB"
        threat_id = "2147918529"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 45 0c 8a 4d 08 88 c2 02 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 30 c8 0f b6 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_PWH_2147919002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.PWH!MTB"
        threat_id = "2147919002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e5 8a 45 ?? 8a 4d ?? 88 c2 02 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_KAA_2147919039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.KAA!MTB"
        threat_id = "2147919039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e5 8a 45 [0-15] 88 c2 02 15 [0-50] 30 c8 0f b6 c0 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GBX_2147919209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GBX!MTB"
        threat_id = "2147919209"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 c2 02 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c0 5d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_SNUK_2147919835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.SNUK!MTB"
        threat_id = "2147919835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 4d 08 88 c2 02 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 0f b6 c0 5e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_ASAQ_2147920295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.ASAQ!MTB"
        threat_id = "2147920295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 89 e5 50 8a 45 0c 8a 4d 08 88 0d [0-4] a2 [0-4] 30 c8 a2 [0-4] 8b 15 [0-4] 81 c2 [0-4] 89 15 [0-4] 88 45 ff c7 05 [0-8] 8a 45 ff 0f b6 c0 83 c4 04 5d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GND_2147920724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GND!MTB"
        threat_id = "2147920724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 f2 88 d0 88 45 ?? 8b 15 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 45 ?? 83 c4 ?? 5e 5d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GZP_2147921003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GZP!MTB"
        threat_id = "2147921003"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5d c3 8d 05 ?? ?? ?? ?? 31 20 e8 ?? ?? ?? ?? c3 01 2d ?? ?? ?? ?? e8 ?? ?? ?? ?? 01 d0 8d 05 ?? ?? ?? ?? 89 30 42 29 d0 8d 05 ?? ?? ?? ?? 01 38 89 d8 50}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_SEZC_2147921058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.SEZC!MTB"
        threat_id = "2147921058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 c4 02 25 ?? ?? ?? ?? 88 25 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? a2 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 30 c8 0f b6 c0 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_AMA_2147921785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.AMA!MTB"
        threat_id = "2147921785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 8a 45 0c 8a 4d 08 88 0d [0-40] 30 c8 [0-20] c7 05 [0-20] 0f b6 c0 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_AMB_2147921789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.AMB!MTB"
        threat_id = "2147921789"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 56 50 8a 45 0c 8a 4d 08 88 45 fb 88 4d fa 0f b6 55 fa 0f b6 35 [0-50] 01 f2 88 d0 a2 [0-40] c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8a 45 [0-31] c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? 0f b6 35 ?? ?? ?? ?? 31 f2 88 d0 a2 [0-80] 83 c4 04 5e 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GCN_2147922472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GCN!MTB"
        threat_id = "2147922472"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 28 8d 05 ?? ?? ?? ?? 89 18 83 e8 ?? 01 d0 31 d0 89 f8 50 8f 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_SFDB_2147922824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.SFDB!MTB"
        threat_id = "2147922824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SkeiOeitxnese" ascii //weight: 2
        $x_1_2 = "tedsrtamol30.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GZT_2147922894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GZT!MTB"
        threat_id = "2147922894"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 42 8d 05 ?? ?? ?? ?? 31 20 89 d0 83 f0 ?? e8 ?? ?? ?? ?? c3 48 4a 01 d0 29 c2 89 35 ?? ?? ?? ?? 4a 42 40 89 2d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GNE_2147925045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GNE!MTB"
        threat_id = "2147925045"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 38 42 29 c2 31 d0 8d 05 ?? ?? ?? ?? 89 28 31 d0 89 35 ?? ?? ?? ?? 83 f2 ?? 4a 48 31 1d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_PPHH_2147926926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.PPHH!MTB"
        threat_id = "2147926926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 50 8a 45 0c 8a 4d 08 88 45 fb 88 4d fa 0f b6 55 fa 0f b6 35 ?? ?? ?? ?? 01 f2 88 d0 a2 ?? ?? ?? ?? 0f b6 55 fb 0f b6 35 ?? ?? ?? ?? 01 f2 88 d0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_PPVH_2147927418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.PPVH!MTB"
        threat_id = "2147927418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 88 c5 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 0f b6 c4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_PQGH_2147927863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.PQGH!MTB"
        threat_id = "2147927863"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 88 c5 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? a2 ?? ?? ?? ?? 0f b6 c4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_PLBH_2147928721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.PLBH!MTB"
        threat_id = "2147928721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 88 c5 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GTM_2147929121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GTM!MTB"
        threat_id = "2147929121"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e5 56 8a 45 ?? 8a 4d ?? 31 d2 88 d4 8b 15 ?? ?? ?? ?? 89 d6 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 88 c5 02 2d ?? ?? ?? ?? 88 2d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GTG_2147929388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GTG!MTB"
        threat_id = "2147929388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 38 8d 05 ?? ?? ?? ?? 31 28 40 8d 05 ?? ?? ?? ?? 31 30 8d 05 ?? ?? ?? ?? 31 18 8d 05 ?? ?? ?? ?? 50 c3 b9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_SAA_2147929845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.SAA"
        threat_id = "2147929845"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "cmd.exe" wide //weight: 10
        $x_10_2 = "net use" wide //weight: 10
        $x_10_3 = ".si@ssl\\" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_AMDC_2147931539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.AMDC!MTB"
        threat_id = "2147931539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 56 8a 45 0c 8a 4d 08 31 d2 88 d4 [0-30] 8b 15 ?? ?? ?? ?? 89 d6 81 c6 ?? ?? ?? ?? 89 35 [0-21] 0f b6 c4 5e 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_PHA_2147932937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.PHA!MTB"
        threat_id = "2147932937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 8b 15 ?? ?? ?? ?? 88 c5 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c4 5d c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_PHB_2147933649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.PHB!MTB"
        threat_id = "2147933649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 88 c5 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c4 5d c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_PHQ_2147934478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.PHQ!MTB"
        threat_id = "2147934478"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 88 c5 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c4 5d c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_HHT_2147935812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.HHT!MTB"
        threat_id = "2147935812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 88 cd 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c4 5d c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_ZHZ_2147937263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.ZHZ!MTB"
        threat_id = "2147937263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {50 8a 45 0c 8a 4d 08 31 d2 88 d4 88 45 fb 88 4d fa 0f b6 55 fa 0f b6 35 ?? ?? ?? ?? 01 f2 88 d0 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8a 45 fa a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8a 45 fb a2 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 89 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c4 83 c4 04 5e 5d c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GTY_2147937540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GTY!MTB"
        threat_id = "2147937540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 18 01 d0 8d 05 ?? ?? ?? ?? 31 d2 89 10 31 28 89 c2 01 d0 8d 05 ?? ?? ?? ?? 31 d2 89 10 31 38 b9 02 00 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_ZZJ_2147937997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.ZZJ!MTB"
        threat_id = "2147937997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 8b 15 ?? ?? ?? ?? 88 cd 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c4 5d c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_ZZY_2147938642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.ZZY!MTB"
        threat_id = "2147938642"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 89 e5 53 81 ec ?? ?? ?? ?? a1 ?? ?? ?? ?? 8a 08 88 8d ?? ?? ?? ?? b8 ?? ?? ?? ?? 8a 8d ?? ?? ?? ?? 80 f9 ?? 89 85 ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? 8b 85 e0 fe ff ff 81 c4 ?? ?? ?? ?? 5b 5d c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GTB_2147939772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GTB!MTB"
        threat_id = "2147939772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 d0 31 d2 89 15 ?? ?? ?? ?? 01 35 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 31 d2 89 10 31 18}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GYZ_2147940324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GYZ!MTB"
        threat_id = "2147940324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c0 04 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 31 2d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 31 3d ?? ?? ?? ?? e9 ?? ?? ?? ?? c3 4a 01 c2 89 d0 31 c2 31 d2 89 15 ?? ?? ?? ?? 01 1d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_ZRY_2147940632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.ZRY!MTB"
        threat_id = "2147940632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 d0 88 c1 88 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 2d ?? ?? ?? ?? a3 ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 83 c4 08 5e 5d c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_GZZ_2147940876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.GZZ!MTB"
        threat_id = "2147940876"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {42 31 d2 89 15 ?? ?? ?? ?? 01 1d ?? ?? ?? ?? 31 d0 42 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 35 ?? ?? ?? ?? b9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_ZCV_2147941135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.ZCV!MTB"
        threat_id = "2147941135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 89 e5 56 8a 45 0c 8a 4d 08 b2 01 88 cc 02 25 ?? ?? ?? ?? 88 25 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c2 5e 5d c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_ZEV_2147941143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.ZEV!MTB"
        threat_id = "2147941143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 89 e5 56 50 8a 45 0c 8a 4d 08 31 d2 88 d4 88 45 fb 88 4d fa 0f b6 55 fa 0f b6 35 ?? ?? ?? ?? 01 f2 88 d0 a2 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 89 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8a 45 fa a2 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8a 45 fb a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c4 83 c4 04 5e 5d c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_BH_2147941357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.BH!MTB"
        threat_id = "2147941357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {29 c2 83 ea ?? b8 ?? ?? ?? ?? 31 d2 89 15 ?? ?? ?? ?? 01 25 ?? ?? ?? ?? 31 d0 31 c2 29 c2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fauppod_ZTV_2147941598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fauppod.ZTV!MTB"
        threat_id = "2147941598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fauppod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 89 e5 57 56 8a 45 0c 8a 4d 08 b2 01 8b 35 ?? ?? ?? ?? 89 f7 81 c7 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 88 c4 02 25 ?? ?? ?? ?? 88 25 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 0f b6 c2 5e 5f 5d c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

