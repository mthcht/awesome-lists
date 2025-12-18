rule Trojan_Win64_Rozena_AF_2147781772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.AF!MTB"
        threat_id = "2147781772"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Dll6.dll" ascii //weight: 3
        $x_3_2 = "dirtree_" ascii //weight: 3
        $x_3_3 = "c:/bindata" ascii //weight: 3
        $x_3_4 = "Software\\SilverSpaceship\\stb" ascii //weight: 3
        $x_3_5 = "%s/%s.cfg" ascii //weight: 3
        $x_3_6 = "TbDiRtReE02" ascii //weight: 3
        $x_3_7 = "%s to convert '%S' to %s!" ascii //weight: 3
        $x_3_8 = "LocaleNameToLCID" ascii //weight: 3
        $x_3_9 = "AppPolicyGetProcessTerminationMethod" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_IG_2147830485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.IG!MTB"
        threat_id = "2147830485"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 fc 48 63 d0 48 8b 45 10 48 01 d0 0f b6 10 8b 45 fc 48 63 c8 48 8b 45 10 48 01 c8 83 f2 01 88 10 83 45 fc 01 8b 45 fc 3b 45 f8 7c d2 48 8b 45 10 48 83 c4 30 5d c3}  //weight: 10, accuracy: High
        $x_1_2 = "socket" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_RA_2147838422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.RA!MTB"
        threat_id = "2147838422"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 b9 5c 41 70 70 44 61 74 61 48 89 08 48 bf 5c 4c 6f 63 61 6c 5c 42 48 89 78 08 48 ba 72 6f 77 73 65 72 45 78 48 89 50 10 48 b9 74 65 6e 73 69 6f 6e 00 48 89 48 18 48 8d 85 90 03 00 00 48 bf 43 3a 5c 50 72 6f 67 72 48 89 38 48 ba 61 6d 44 61 74 61 5c 42}  //weight: 1, accuracy: High
        $x_1_2 = "schtasks /delete /tn BrowserCleanup /f" ascii //weight: 1
        $x_1_3 = "schtasks /delete /tn BrowserUpdate /f" ascii //weight: 1
        $x_1_4 = "Done screenshot" ascii //weight: 1
        $x_1_5 = "Please create keylog file first" ascii //weight: 1
        $x_1_6 = "del /F /Q log.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_AR_2147839749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.AR!MTB"
        threat_id = "2147839749"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f3 0f 6f 41 e0 83 c0 40 48 8d 49 40 66 0f f8 c2 f3 0f 7f 41 a0 f3 0f 6f 41 b0 66 0f f8 c2 f3 0f 7f 41 b0 f3 0f 6f 49 c0 66 0f f8 ca f3 0f 7f 49 c0 f3 0f 6f 41 d0 66 0f f8 c2 f3 0f 7f 41 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_RD_2147839883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.RD!MTB"
        threat_id = "2147839883"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 4a 40 8b 48 48 89 4a 48 0f b7 48 4c 66 89 4a 4c 33 c9 ba ce 01 00 00 44 8d 49 40 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_RD_2147839883_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.RD!MTB"
        threat_id = "2147839883"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 ff c2 48 83 fa 0b 72 f0 07 00 8d 42 ?? 30 44 15}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 85 b8 00 00 00 43 5d 5e 48 c7 85 bc 00 00 00 52 48 44 10 c7 85 c0 00 00 00 11 6e 00 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_RE_2147839900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.RE!MTB"
        threat_id = "2147839900"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 63 c1 48 8d 54 24 ?? 48 03 d0 8d 41 ?? 30 02 ff c1 83 f9 03 72 e9}  //weight: 5, accuracy: Low
        $x_1_2 = "discord" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_PC_2147841490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.PC!MTB"
        threat_id = "2147841490"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 0f af c2 48 c1 e8 ?? 89 c2 c1 ea ?? 89 d0 c1 e0 ?? 01 d0 c1 e0 ?? 29 c1 89 ca 89 d2 48 ?? ?? ?? ?? ?? ?? 0f b6 04 02 89 c1 8b 45 ?? 48 63 d0 48 8b 45 ?? 48 01 d0 44 89 c2 31 ca 88 10 83 45 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_SPH_2147846384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.SPH!MTB"
        threat_id = "2147846384"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 0f b6 0c 11 80 f1 7e 88 0a 41 ff c0 48 8d 52 01 49 63 c0 48 3b c7 72}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_CAFW_2147846591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.CAFW!MTB"
        threat_id = "2147846591"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 10 00 00 00 49 89 c8 48 89 c1 e8 ?? ?? ?? ?? 48 8b 85 e0 03 01 00 41 b9 40 00 00 00 41 b8 00 10 00 00 48 89 c2 b9 00 00 00 00 48 8b 05 75 6a 01 00 ff ?? 48 89 85 d8 03 01 00 48 8b 05 05 6a 01 00 ff ?? 48 89 c1 4c 8b 85 e0 03 01 00 48 8d 55 b0 48 8b 85 d8 03 01 00 48 c7 44 24 20 00 00 00 00 4d 89 c1 49 89 d0 48 89 c2 48 8b 05 4d 6a 01 00 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_SPF_2147846619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.SPF!MTB"
        threat_id = "2147846619"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c7 45 fc 00 00 00 00 8b 45 f8 48 63 d0 48 8b 45 10 48 01 d0 44 0f b6 00 8b 45 fc 48 63 d0 48 8b 45 20 48 01 d0 0f b6 08 8b 45 f8 48 63 d0 48 8b 45 10 48 01 d0 44 89 c2 31 ca 88 10 83 45 fc 01 83 45 f8 01 eb 9d}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_SPF_2147846619_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.SPF!MTB"
        threat_id = "2147846619"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8d 4c 24 50 41 b8 ff 03 00 00 48 8d 55 f0 48 8b cf ff 15 ?? ?? ?? ?? 44 8b 4c 24 50 4c 8d 45 f0 48 8b 54 24 60 48 8d 4c 24 58 e8 ?? ?? ?? ?? 83 7c 24 50 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 7c 24 60 48 8b 74 24 58 48 2b fe 41 b9 ?? ?? ?? ?? 41 b8 ?? ?? ?? ?? 48 8b d7 33 c9 ff 15 ?? ?? ?? ?? 48 8b d8 4c 8b c7 48 8b d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_SPQ_2147847220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.SPQ!MTB"
        threat_id = "2147847220"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://10.211.55.2:8081/jquery.com/download/3.6.4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_SP_2147847747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.SP!MTB"
        threat_id = "2147847747"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f3 0f 6f 41 f0 48 8d 49 40 0f 57 c9 66 0f f8 c8 f3 0f 7f 49 b0 0f 57 c9 f3 0f 6f 41 c0 66 0f f8 c8 f3 0f 7f 49 c0 0f 57 c9 f3 0f 6f 41 d0 66 0f f8 c8 f3 0f 7f 49 d0 0f 57 c9 f3 0f 6f 41 e0 66 0f f8 c8 f3 0f 7f 49 e0 48 83 ea 01 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_HLC_2147847807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.HLC!MTB"
        threat_id = "2147847807"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 cf 5d 01 00 99 f7 7d d8 89 d0 83 c0 01 31 c3 89 d9 8b 45 ac 48 98 48 8b 55 a0 48 01 d0 89 ca 88 10 8b 45 ac 48 98 48 8b 55 a0 48 01 d0 0f b6 08 8b 45 e0 41 89 c0 8b 45 ac 48 98 48 8b 55 a0 48 01 d0 44 31 c1 89 ca 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_ASG_2147850823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.ASG!MTB"
        threat_id = "2147850823"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f 1f 00 80 30 ?? 48 8d 40 01 ff c1 81 f9 ?? ?? ?? ?? 72 ef 48 8d 84 24 ?? ?? ?? ?? 45 33 c9 48 89 44 24 ?? 33 d2 33 c9 c7 44 24 20 ?? ?? ?? ?? ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_EN_2147851462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.EN!MTB"
        threat_id = "2147851462"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {89 55 ec 48 8b 4d c8 48 63 d0 8b 45 f0 48 98 48 0f af c3 48 01 ca 48 01 d0 0f b6 10 8b 45 f4 48 63 c8 48 8b 45 c0 48 01 c8 88 10}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_EN_2147851462_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.EN!MTB"
        threat_id = "2147851462"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {88 84 24 e0 01 00 00 8b c1 c1 e8 08 88 84 24 e1 01 00 00 8b c1 c1 e8 10 45 8d 41 06 88 84 24 e2 01 00 00 0f b6 44 24 22 88 84 24 e4 01 00 00 0f b7 44 24 22 c1 e9 18 66 c1 e8 08 88 8c 24 e3 01 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_RC_2147851527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.RC!MTB"
        threat_id = "2147851527"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {df c6 cb b6 c7 85 ?? ?? 00 00 57 35 9c 21 c7 85 ?? ?? 00 00 78 9f 93 38 c7 85 ?? ?? 00 00 1e d4 01 58 c7 85 ?? ?? 00 00 24 c9 71 7f c7 85 ?? ?? 00 00 ad 56 74 8a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_AMAB_2147852296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.AMAB!MTB"
        threat_id = "2147852296"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 3b 45 18 7d ?? 8b 45 fc 48 98 48 8b 55 28 48 83 ea 01 48 39 d0 75 ?? c7 45 fc ?? ?? ?? ?? 8b 45 f8 48 63 d0 48 8b 45 10 48 01 d0 44 0f b6 00 8b 45 fc 48 63 d0 48 8b 45 20 48 01 d0 0f b6 08 8b 45 f8 48 63 d0 48 8b 45 10 48 01 d0 44 89 c2 31 ca 88 10 83 45 fc 01 83 45 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_EM_2147889023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.EM!MTB"
        threat_id = "2147889023"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {48 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 00 00 c7 44 24 20 03 00 00 00 41 b9 00 00 00 00 41 b8 01 00 00 00 ba 00 00 00 80}  //weight: 3, accuracy: High
        $x_3_2 = {48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 41 b9 00 00 00 00 41 b8 02 00 00 01 ba 00 00 00 00 48 89 c1}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_PABB_2147890331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.PABB!MTB"
        threat_id = "2147890331"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 d0 48 69 d2 d3 4d 62 10 48 c1 ea 20 c1 fa 06 89 c1 c1 f9 1f 29 ca 69 ca e8 03 00 00 29 c8 89 c2 66 0f ef f6 f2 0f 2a f2 e8 ?? ?? ?? 00 48 63 d0 48 69 d2 eb a0 0e ea 48 c1 ea 20 01 c2 c1 fa 06 89 c1 c1 f9 1f 29 ca 6b ca 46 29 c8 89 c2 66 0f ef c9 f2 0f 2a ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_NR_2147890496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.NR!MTB"
        threat_id = "2147890496"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8d 0d da fd ff ff 48 89 02 e8 da 40 00 00 e8 4d 36 00 00 48 63 1d ?? ?? ?? ?? 8d 4b 01 48 63 c9}  //weight: 3, accuracy: Low
        $x_3_2 = {48 c1 e1 03 e8 6f 41 00 00 4c 8b 35 ?? ?? ?? ?? 49 89 c5 44 39 e3 7e 2b 4b 8b 0c e6 e8 6f 41 00 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_NR_2147890496_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.NR!MTB"
        threat_id = "2147890496"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {75 24 48 8b 05 c9 e6 10 00 48 83 f8 00 74 06 48 83 38 00 75 11 48 8d 05 8e 4d 00 00 ff d0}  //weight: 2, accuracy: High
        $x_1_2 = {e8 7d ff ff ff 48 8b 0d e6 3c 15 00 65 48 8b 09 48 8b 7c 24 08 48 8b 77 08 48 2b 34 24 48 89 39 48 89 f4 89 44 24 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_NR_2147890496_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.NR!MTB"
        threat_id = "2147890496"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {e8 5d 2c ff ff 48 89 6b ?? 48 8b 2d 52 40 01 00 41 bb ?? ?? ?? ?? 4c 89 23 4c}  //weight: 3, accuracy: Low
        $x_3_2 = {45 31 c0 4c 89 e1 48 8b 05 f9 41 01 00 66 44 89 87 ?? ?? ?? ?? 48 c7 87 e8 00 00 00 ?? ?? ?? ?? 48 8d 50 18 48 83 c0 40}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_NR_2147890496_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.NR!MTB"
        threat_id = "2147890496"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8d 0d c3 99 12 00 48 8b 01 48 05 ?? ?? ?? ?? 48 89 41 10 48 89 41 18}  //weight: 3, accuracy: Low
        $x_3_2 = {48 8d 3d 63 9f 12 00 e8 c6 3f 00 00 65 48 8b 1c 25 ?? ?? ?? ?? 48 c7 83 00 00 00 00 23 01 00 00 48 8b 05 ?? ?? ?? ?? 48 3d 23 01 00 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_NR_2147890496_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.NR!MTB"
        threat_id = "2147890496"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8b 35 7b e0 55 00 65 48 8b 04 25 30 00 00 00 48 8b 58 08 31 c0 f0 48 0f b1 5d 00 74 ?? 48 39 c3 74 ?? b9 e8 03 00 00}  //weight: 3, accuracy: Low
        $x_2_2 = {8d 4b 01 48 63 c9 48 c1 e1 03 e8 ?? ?? ?? ?? 4c 8b 35 d0 bd 55 00 49 89 c5 44 39 e3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_NR_2147890496_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.NR!MTB"
        threat_id = "2147890496"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 89 5c 24 20 48 8d 05 7d 71 1c 00 e8 ?? ?? ?? ?? 48 8b 4c 24 10 48 89 08 48 8b 4c 24 20 48 8b 11 48 89 50 10 48 89 01}  //weight: 3, accuracy: Low
        $x_2_2 = {48 8d 15 1d 7b 0c 00 48 89 c6 48 8b 44 24 40 48 89 df 48 89 f3 49 89 c8 48 89 f9 41 ff d0 48 8b 4c 24 40 48 8d 14 49}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_NR_2147890496_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.NR!MTB"
        threat_id = "2147890496"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {eb 33 66 0f 6f 05 ?? ?? ?? ?? 48 83 c8 ff f3 0f 7f 05 ?? ?? ?? ?? 48 89 05 0e cf 94 00 f3 0f 7f 05 ?? ?? ?? ?? 48 89 05 17 cf 94}  //weight: 5, accuracy: Low
        $x_1_2 = "steam_module_x64.pdb" ascii //weight: 1
        $x_1_3 = "primordial_crack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_NR_2147890496_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.NR!MTB"
        threat_id = "2147890496"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ff d0 85 c0 75 07 b8 ff ff ff ff eb 75 48 8b 4d ?? 48 8d 45 ?? 48 89 44 24 ?? 48 8b 45 ?? 48 89 44 24 ?? 41 b9 00 00 00 00 41 b8 00 00 00 00 ba}  //weight: 3, accuracy: Low
        $x_2_2 = {e9 a8 00 00 00 48 8b 55 ?? 48 8b 4d ?? 48 8d 45 ?? 48 89 44 24 ?? 41 b9 00 00 00 00 49 89 d0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_NR_2147890496_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.NR!MTB"
        threat_id = "2147890496"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8d 15 6b 22 00 00 ff 15 95 20 00 00 b9 ?? ?? 00 00 66 89 bd ?? ?? 00 00 ff 15 7b 20 00 00 44 8d 47 0e 48 8b cb 48 8d 95 ?? ?? 00 00 66 89 85 ?? ?? 00 00 ff 15 80 20 00 00}  //weight: 3, accuracy: Low
        $x_3_2 = {ff 15 cd 1d 00 00 48 89 74 24 ?? 4c 8b cb 89 74 24 ?? 45 33 c0 33 d2 48 89 74 24 ?? 48 8b cf ff 15 c6 1d 00 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_PY_2147895936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.PY!MTB"
        threat_id = "2147895936"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "amzdjjekqcsebt&ax1xhrzwqjumwhluaamzdjjekqcsebtfaxsx" ascii //weight: 1
        $x_5_2 = {49 89 c0 41 83 e0 1f 42 32 0c 02 88 0c 03 48 83 c0 01 39 f0 72 b1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_BAN_2147895962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.BAN!MTB"
        threat_id = "2147895962"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4e 8d 0c 03 4d 39 d0 7d 2c 42 8d 0c 03 42 32 4c 00 10 4c 89 ca 48 c1 fa 08 31 d1 4c 89 ca 49 c1 f9 18 48 c1 fa 10 31 d1 44 31 c9 42 88 4c 00 10 49 ff c0 eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_SPK_2147896063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.SPK!MTB"
        threat_id = "2147896063"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f3 0f 6f 40 e0 66 0f ef c2 f3 0f 7f 40 e0 f3 0f 6f 40 f0 66 0f 6f ca 66 0f ef c8 f3 0f 7f 48 f0 f3 0f 6f 00 66 0f 6f ca 66 0f ef c8 f3 0f 7f 08 f3 0f 6f 40 10 66 0f ef c2 f3 0f 7f 40 10 48 83 c1 40 48 8d 40 40 48 3b ca 7c b5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_AMBE_2147900884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.AMBE!MTB"
        threat_id = "2147900884"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fc 48 83 e4 f0 e8 c0 00 00 00 41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52}  //weight: 1, accuracy: High
        $x_1_2 = {01 d0 41 8b 04 88 48 01 d0 41 58 41 58 5e 59 5a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_N_2147902657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.N!MTB"
        threat_id = "2147902657"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {4c 8b 4c 24 30 4c 89 4c ca 18 eb ?? 4c 8b 4c 24 30 e8 68 6e 04 00 4c 8b 4c 24 38}  //weight: 3, accuracy: Low
        $x_1_2 = "Yihsiwei" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_N_2147902657_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.N!MTB"
        threat_id = "2147902657"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8b 2d b0 32 0e 00 31 ff 65 48 8b 04 25 ?? ?? ?? ?? 48 8b 70 08}  //weight: 3, accuracy: Low
        $x_3_2 = {48 8b 05 e3 2f 0e 00 ff d0 bb ?? ?? ?? ?? 48 8d 45 d0 48 89 c1 e8 d0 f0 09 00 89 d8}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_NA_2147902718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.NA!MTB"
        threat_id = "2147902718"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 89 44 f2 10 48 8d 3c f2 83 3d a2 4d 1b 00 ?? 75 09 4c 89 04 f2}  //weight: 3, accuracy: Low
        $x_3_2 = {75 24 48 8b 44 24 ?? 48 89 81 08 01 01 00 48 8b 05 4d d0 16 00 48 89 81 f8 00 01 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_NA_2147902718_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.NA!MTB"
        threat_id = "2147902718"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f 11 74 24 40 0f 11 7c 24 ?? 44 0f 11 44 24 ?? 83 39 06 0f 87 cd 00 00 00 8b 01 48 8d 15 ?? ?? ?? ?? 48 63 04 82 48 01 d0}  //weight: 3, accuracy: Low
        $x_3_2 = {48 8b 4c 24 20 48 8b 54 24 ?? 41 b8 40 00 00 00 48 03 3d ?? ?? ?? ?? 48 89 4f 08 49 89 f9 48 89 57 ?? ff 15 9c 5e 0c 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_NER_2147902800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.NER!MTB"
        threat_id = "2147902800"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {4c 8d 04 02 48 63 c1 48 69 c0 ?? ?? ?? ?? 48 c1 e8 20 89 c2}  //weight: 3, accuracy: Low
        $x_3_2 = {01 d0 8d 14 85 ?? ?? ?? ?? 01 d0 29 c1 89 ca 41 89 10}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_NE_2147902801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.NE!MTB"
        threat_id = "2147902801"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8b 95 e8 01 00 00 4c 8d 04 11 48 63 d0 48 69 d2 ?? ?? ?? ?? 48 c1 ea 20 c1 fa 05 89 c1}  //weight: 3, accuracy: Low
        $x_3_2 = {c1 f9 1f 29 ca 69 ca ?? ?? ?? ?? 29 c8 89 c2 41 89 10 83 85}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_NEP_2147902948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.NEP!MTB"
        threat_id = "2147902948"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {e8 73 a4 00 00 f2 44 0f 11 44 24 ?? 49 89 d8 48 8d 15 7a 14 0b 00 f2 0f 11 7c 24 ?? 48 89 c1 49}  //weight: 3, accuracy: Low
        $x_3_2 = {e8 c2 a6 09 00 4c 8d 05 ?? ?? ?? ?? 48 8d 15 44 62 0a 00 48 89 c1 48 8d 05 ?? ?? ?? ?? 48 89 01 e8}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_EC_2147903538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.EC!MTB"
        threat_id = "2147903538"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ETW patched !" ascii //weight: 1
        $x_1_2 = "Opening a handle on spoolsv process" ascii //weight: 1
        $x_1_3 = "Preparing the venoma" ascii //weight: 1
        $x_1_4 = "Shellcode executed" ascii //weight: 1
        $x_1_5 = "Beginning self-deletion process" ascii //weight: 1
        $x_1_6 = "Renaming :$DATA to %s" ascii //weight: 1
        $x_1_7 = "Deleting binary file" ascii //weight: 1
        $x_1_8 = "Venoma.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_XZ_2147904500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.XZ!MTB"
        threat_id = "2147904500"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 44 24 08 48 8b 4c 24 40 48 89 08 0f 57 c0 0f 11 40 08 48 8b 54 24 48 48 89 50 18 0f 11 40 20 48 c7 40 30 00 00 00 00 48 8b 15 70 af 0d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_NG_2147906169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.NG!MTB"
        threat_id = "2147906169"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8d 14 c5 00 00 00 00 48 8b 85 ?? ?? ?? ?? 48 01 d0 48 8b 00 8b 95 ?? ?? ?? ?? 48 63 d2 48 8d 0c d5 ?? ?? ?? ?? 48 8b 95 28 08 00 00}  //weight: 3, accuracy: Low
        $x_3_2 = {48 c7 44 24 40 00 00 00 00 48 8d 85 08 08 00 00 48 89 44 24 38 48 c7 44 24 30 00 00 00 00 c7 44 24 28 1f 00 02 00 c7 44 24 20 00 00 00 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_NRE_2147906760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.NRE!MTB"
        threat_id = "2147906760"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {44 8b 0f 45 85 c9 0f 85 9c 02 00 00 65 48 8b 04 25 ?? ?? ?? ?? 48 8b 1d 0c 92 05 00 48 8b 70 ?? 31 ed 4c 8b 25 0b e0 05 00 eb 16}  //weight: 3, accuracy: Low
        $x_3_2 = {48 85 c0 75 e2 48 8b 35 e3 91 05 00 31 ed 8b 06 83 f8 ?? 0f 84 05 02 00 00 8b 06}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_NM_2147907686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.NM!MTB"
        threat_id = "2147907686"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {eb 15 e8 a9 02 03 00 48 8b 44 24 ?? 49 89 03 48 8b 4a ?? 49 89 4b 08 48 89 42 ?? 48 c7 42 18 ?? ?? ?? ?? 48 83 c4 18}  //weight: 3, accuracy: Low
        $x_3_2 = {48 89 44 24 ?? 48 89 5c 24 ?? e8 78 e3 02 00 48 8b 44 24 ?? 48 8b 5c 24 ?? e9 69 ff ff ff}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_NM_2147907686_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.NM!MTB"
        threat_id = "2147907686"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 83 ec 28 e8 cf 07 ?? ?? 85 c0 74 21 65 48 8b 04 25 30 00 00 00 48 8b 48 08 eb ?? 48 3b c8 74 ?? 33 c0 f0 48 0f b1 0d 34 97 01 00 75 ?? 32 c0 48 83}  //weight: 3, accuracy: Low
        $x_2_2 = {40 53 48 83 ec 20 80 3d e4 96 01 00 00 8b d9 75 ?? 83 f9 01 77 ?? e8 45 07 00 00 85 c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_NM_2147907686_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.NM!MTB"
        threat_id = "2147907686"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b 44 24 ?? 45 33 c0 ba ?? ?? ?? ?? 48 8b c8 e8 6d 15 f3 ff 48 8b 44 24}  //weight: 2, accuracy: Low
        $x_3_2 = {eb 0a 8b 44 24 30 ff c0 89 44 24 ?? 48 63 44 24 ?? 48 83 f8 05 73 11 48 63 44 24 ?? 48 8b 4c 24 ?? c6 44 01 3e 00 eb da e9 fa fe ff ff 48 8d 4c 24 ?? e8 50 18 f3 ff 48 89 44 24 ?? 48 8d 4c 24 ?? e8 16 fd f2 ff}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_NI_2147908642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.NI!MTB"
        threat_id = "2147908642"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {74 26 48 89 5c 24 ?? 48 89 4c 24 ?? 48 89 44 24 ?? 48 89 cb e8 18 96 fa ff 48 8b 44 24 20}  //weight: 3, accuracy: Low
        $x_3_2 = {e8 bb 95 fa ff 48 8b 44 24 ?? 48 8b 5c 24 ?? 48 89 5c 24 ?? e8 87 a8 00 00 48 83 c4 20}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_NP_2147909802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.NP!MTB"
        threat_id = "2147909802"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 83 ec 18 48 8b 44 24 ?? 48 83 f8 00 75 18 48 8b 0d fe a8 0d 00 65 48 8b 09 48 8b 5c 24 30}  //weight: 3, accuracy: Low
        $x_3_2 = {48 89 19 e9 20 01 00 00 48 8b 0d e6 a8 0d 00 65 48 8b 09 bb ?? ?? ?? ?? 48 83 f9 00 74 03}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_NK_2147909803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.NK!MTB"
        threat_id = "2147909803"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8b 2d da 17 98 00 48 8b 35 7b 60 98 00 65 48 8b 04 25 ?? ?? ?? ?? 48 8b 58 08 31 c0 f0 48 0f b1 5d 00 74 0e}  //weight: 3, accuracy: Low
        $x_3_2 = {74 0d b9 e8 03 00 00 ff d6 eb e8 31 f6 eb 05 be ?? ?? ?? ?? 48 8b 1d ae 17 98 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_HNI_2147910484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.HNI!MTB"
        threat_id = "2147910484"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 ec 20 41 52 ff e0 58 41 59 5a 48 8b 12 e9 4f ff ff ff 5d 6a 00 49 be 77 69 6e 69 6e 65 74 00 41 56 49 89 e6 4c 89 f1 41 ba 09 54 88 c9 ff d5 48}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_NN_2147912528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.NN!MTB"
        threat_id = "2147912528"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 c7 44 24 48 00 00 00 00 48 8b 0d ?? a6 2e 00 65 48 8b 09 48 8b 09 48 8b 49}  //weight: 3, accuracy: Low
        $x_3_2 = {48 8d 54 24 20 48 89 91 ?? ?? ?? ?? 48 8b 44 24 ?? 45 0f 57 ff 4c 8b 35 ?? a6 2e 00 65 4d 8b 36 4d 8b 36}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_WIL_2147913015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.WIL!MTB"
        threat_id = "2147913015"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c1 48 8b 1d 7a 98 04 00 89 35 d6 73 04 00 33 95 7b ff ff ff 8a 75 9f 2b 15 ae 84 04 00 89 5d 85 8b 7d a7 81 ef 02 23 00 00 48 8b 5d d4 48 c7 c0 ?? ?? ?? ?? 8b 55 de ba c5 4e 00 00 4c 3b 15 92 8f 04 00 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_ARZ_2147913053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.ARZ!MTB"
        threat_id = "2147913053"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c6 c1 ee 18 45 33 84 b2 ?? ?? ?? ?? 0f b6 f6 0f b6 d4 c1 e8 10 45 33 84 b2 ?? ?? ?? ?? 47 33 84 8a ?? ?? ?? ?? 44 0f b6 c8 43 8b 84 8a ?? ?? ?? ?? 45 33 84 92 ?? ?? ?? ?? 44 31 c0 4c 39 db}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_HNJ_2147913724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.HNJ!MTB"
        threat_id = "2147913724"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 40 57 00 73 00 48 05 ?? ?? 00 00 c7 44 24 44 32 00 5f 00 48 ba ?? ?? ?? ?? 90 51 b1 56 c7 44 24 48 33 00 32 00 c7 44 24 4c 2e 00 64 00 c7 44 24 50 6c 00 6c 00 4c 8d 78 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_BAO_2147917656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.BAO!MTB"
        threat_id = "2147917656"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 fc 48 8b 55 ?? 48 01 d0 0f b6 00 8b 55 fc 48 8b 4d ?? 48 01 ca 32 45 ?? 88 02 83 45 fc 01 8b 45 fc 3b 45 ?? 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_ASJ_2147919720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.ASJ!MTB"
        threat_id = "2147919720"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {ff d5 48 89 c3 49 89 c7 4d 31 c9 49 89 f0 48 89 da 48 89 f9 41 ba 02 d9 c8 5f ff d5 83 f8 00 7d 28 58 41 57 59 68 00 40 00 00 41 58 6a 00 5a 41 ba 0b 2f 0f 30 ff d5 57 59 41 ba 75 6e 4d 61 ff d5 49 ff ce e9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_MBXR_2147920578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.MBXR!MTB"
        threat_id = "2147920578"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID: \"5FejNZc9sALG2w-smL6-/SLLUnyv7xTUm1usY-jhL/bCEJJ9QwxQ_BNRCnEZ2x/-HlaRCRD5Jx" ascii //weight: 1
        $x_1_2 = "Twjiwq9dn6R1fQcyiK+wQyHWfaz/BJB+YIpzU/Cv3X" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_ATZ_2147920881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.ATZ!MTB"
        threat_id = "2147920881"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 45 d0 48 01 d0 8b 40 04 89 45 a4 8b 45 28 48 c1 e0 04 48 89 c2 48 8b 45 d0 48 01 d0 48 8b 40 08 48 89 45 a8 8b 45 28 83 c0 01 89 c0 48 c1 e0 04 48 89 c2 48 8b 45 d0 48 01 c2 8b 45 28 48 c1 e0 04 48 89 c1 48 8b 45 d0 48 01 c8 8b 12 89 10 8b 45 28 83 c0 01 89 c0 48 c1 e0 04 48 89 c2 48 8b 45 d0 48 01 c2}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 28 48 c1 e0 04 48 89 c1 48 8b 45 d0 48 01 c8 8b 52 04 89 50 04 8b 45 28 83 c0 01 89 c0 48 c1 e0 04 48 89 c2 48 8b 45 d0 48 01 c2 8b 45 28 48 c1 e0 04 48 89 c1 48 8b 45 d0 48 01 c8 48 8b 52 08 48 89 50 08 8b 45 28 83 c0 01 89 c0 48 c1 e0 04 48 89 c2 48 8b 45 d0 48 01 d0 8b 55 a0 89 10 8b 45 28 83 c0 01 89 c0 48 c1 e0 04 48 89 c2 48 8b 45 d0 48 01 d0 8b 55 a4 89 50 04 8b 45 28 83 c0 01 89 c0 48 c1 e0 04 48 89 c2 48 8b 45 d0 48 01 d0 48 8b 55 a8 48 89 50 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_PAFW_2147926534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.PAFW!MTB"
        threat_id = "2147926534"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 8b 03 48 8b 43 08 4c 29 c0 48 39 c1 73 ?? 4c 8b 0e 4c 8b 56 08 4d 29 ca 48 89 c8 31 d2 49 f7 f2 41 8a 04 11 41 32 04 08 48 8b 17 88 04 0a 48 ff c1 eb}  //weight: 2, accuracy: Low
        $x_2_2 = "Decrypted shellcode" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_PAFX_2147927899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.PAFX!MTB"
        threat_id = "2147927899"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 10 4d 8b c8 48 83 c0 08 4c 03 ca 48 f7 d2 49 33 d1 49 23 d3 74}  //weight: 2, accuracy: High
        $x_2_2 = "Decrypting shellcode" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_NIT_2147929287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.NIT!MTB"
        threat_id = "2147929287"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c7 44 24 74 04 00 00 00 c7 44 24 78 00 10 00 00 c7 44 24 7c 40 00 00 00 48 8d 84 24 d0 00 00 00 48 8b f8 33 c0 b9 68 00 00 00 f3 aa 48 8d 84 24 a8 00 00 00 48 8b f8 33 c0 b9 18 00 00 00 f3 aa}  //weight: 2, accuracy: High
        $x_2_2 = {48 8d 84 24 a8 00 00 00 48 89 44 24 48 48 8d 84 24 d0 00 00 00 48 89 44 24 40 48 c7 44 24 38 00 00 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 04 00 00 00 c7 44 24 20 00 00 00 00 45 33 c9 45 33 c0 33 d2}  //weight: 2, accuracy: High
        $x_1_3 = "VirtualAllocEx" ascii //weight: 1
        $x_1_4 = "WriteProcessMemory" ascii //weight: 1
        $x_1_5 = "QueueUserAPC" ascii //weight: 1
        $x_1_6 = "ResumeThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_BSA_2147929916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.BSA!MTB"
        threat_id = "2147929916"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {e9 5a 5e 0e 00 e9 45 4e 0c 00 e9 b0 3a 08 00 e9 7b 45 1e 00 e9 b6 59 0d 00}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_NBK_2147932690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.NBK!MTB"
        threat_id = "2147932690"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VirtualAlloc" ascii //weight: 1
        $x_1_2 = "PAYLOAD:" ascii //weight: 1
        $x_1_3 = {48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed}  //weight: 1, accuracy: High
        $x_2_4 = {e3 56 4d 31 c9 48 ff c9 41 8b 34 88 48 01 d6 48 31 c0 41 c1 c9 0d ac 41 01 c1 38 e0 75 f1}  //weight: 2, accuracy: High
        $x_1_5 = {41 58 41 58 48 01 d0 5e 59 5a 41 58 41 59 41 5a 48 83 ec 20 41 52 ff e0 58 41 59 5a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_BS_2147936686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.BS!MTB"
        threat_id = "2147936686"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {46 0f b6 1c 0a 45 31 c3 44 88 1c 3e 48 ff c7 4c 89 c8 4c 89 d2 48 39 fa 7e}  //weight: 2, accuracy: High
        $x_2_2 = {49 ff c1 0f b6 14 17 44 31 d2 4d 39 c8 73}  //weight: 2, accuracy: High
        $x_2_3 = {43 88 54 21 ff 48 ff c1 4c 89 d8 4c 89 e2 48 39 cb}  //weight: 2, accuracy: High
        $x_1_4 = "xors7ajsuajas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_DA_2147937491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.DA!MTB"
        threat_id = "2147937491"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Memory dump completed" ascii //weight: 1
        $x_10_2 = "Decoy packet sent" ascii //weight: 10
        $x_1_3 = "MiniDumpWriteDump" ascii //weight: 1
        $x_1_4 = "%s\\dumpfile_%u.dmp" ascii //weight: 1
        $x_1_5 = "Enter receiver IP:" ascii //weight: 1
        $x_1_6 = "Enter receiver port:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_PGR_2147942817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.PGR!MTB"
        threat_id = "2147942817"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 fc 48 98 48 8d 14 85 00 00 00 00 48 8b 45 10 48 01 d0 8b 00 48 63 d0 48 8b 45 18 48 01 d0 8b 55 fc 48 63 ca 48 8b 55 f0 48 01 ca 0f b6 00 88 02 83 45 fc 01 8b 45 fc 3b 45 f8 7c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_PA_2147945686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.PA!MTB"
        threat_id = "2147945686"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 8b d7 48 8b c1 48 8d 5b 01 83 e0 03 48 ff c1 0f b6 44 04 38 30 43 ff 48 83 ea 01 75 ?? 48 8b 5c 24 ?? 48 83 c4 20 5f c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_GVA_2147948171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.GVA!MTB"
        threat_id = "2147948171"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "://110.41.170.231:8000/beacon.bin.enc" ascii //weight: 2
        $x_1_2 = "schtasksshutdown" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_KK_2147949263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.KK!MTB"
        threat_id = "2147949263"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {69 c0 0d 66 19 00 8d ?? ?? ?? ?? ?? 89 d0 c1 f8 1f c1 e8 18 01 c2 0f b6 d2 29 c2 89 d0}  //weight: 20, accuracy: Low
        $x_10_2 = {10 00 00 41 b9 04 00 00 00 41 b8 00 30 00 00 48 89 c2 b9 00 00 00 00 41 ff d2 48}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_ARB_2147949831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.ARB!MTB"
        threat_id = "2147949831"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 01 d0 0f b6 10 0f b6 05 ?? ?? ?? ?? 31 c2 48 8d 0d ?? ?? ?? ?? 48 8b 45 f8 48 01 c8 88 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_CD_2147951006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.CD!MTB"
        threat_id = "2147951006"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {49 89 d0 ba 00 00 00 00 48 89 c1 e8 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? 48 89 c1 e8 ?? ?? ?? ?? 48 89 c2 48 8d 45 ?? 48 89 c1 e8 ?? ?? ?? ?? 41 b9 40 00 00 00 41 b8 00 30 00 00 ba ?? ?? ?? ?? b9 00 00 00 00 48 8b 05 ?? ?? ?? ?? ff d0}  //weight: 3, accuracy: Low
        $x_2_2 = {49 89 d0 48 89 c2 e8 ?? ?? ?? ?? 48 8b 85 ?? ?? ?? ?? ff d0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_AB_2147952698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.AB!MTB"
        threat_id = "2147952698"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 27 00 00 00 48 89 c7 48 89 d6 f3 48 a5 48 89 f2 48 89 f8 0f b7 0a 66 89 08 48 b8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_SPZP_2147953392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.SPZP!MTB"
        threat_id = "2147953392"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {48 31 0a 48 83 c2 08 49 3b d0 72}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_PGRN_2147957038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.PGRN!MTB"
        threat_id = "2147957038"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "powershell -w hidden -nop -e YwBtAGQALgBlAHgAZQAgAC8AYwAgACcAcABvAHcAZQByAHMAaABlAGwAbAAgAC0AdwA" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_ADMB_2147958384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.ADMB!MTB"
        threat_id = "2147958384"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4b 8d 0c 06 33 d2 49 8b c0 49 f7 f2 42 0f b6 04 22 32 04 19 88 01 49 ff c0 4c 3b c7 72}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_APMB_2147958742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.APMB!MTB"
        threat_id = "2147958742"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {99 41 f7 f9 48 63 c2 8a 14 04 48 89 c3 88 14 3c 88 0c 04 02 0c 3c 0f b6 c9 8a 04 0c 43 30 04 02 49 ff c0 eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_LM_2147958750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.LM!MTB"
        threat_id = "2147958750"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {0f be d2 69 d2 2d 15 00 00 4c 63 c2 4d 69 c0 31 0c c3 30 49 c1 f8 22 c1 fa 1f 41 29 d0 41 0f af c1 44 01 c0 48 83 c1 01}  //weight: 20, accuracy: High
        $x_10_2 = {41 56 41 55 41 54 55 57 56 53 48 83 ec 28 48 89 ce 41 89 d4 48 85 c9 0f 94 c0 85 d2 0f 94 c2 08 d0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_MK_2147958981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.MK!MTB"
        threat_id = "2147958981"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {8b 45 fc 48 63 d0 48 8b 45 f0 48 01 d0 0f b6 10 8b 45 fc 48 63 c8 48 8b 45 f0 48 01 c8 83 f2 73 88 10 83 45 fc 01}  //weight: 15, accuracy: High
        $x_10_2 = {48 63 d0 48 69 d2 4f ec c4 4e 48 c1 ea 20 c1 fa 03 89 c1 c1 f9 1f 29 ca 6b ca 1a 29 c8 89 c2 89 d0 83 c0 41 89 c1 8b 45 fc 48 98 48 8d 15 f5 57 00 00 88 0c 10 83 45 fc 01}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_SX_2147959069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.SX!MTB"
        threat_id = "2147959069"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {0f 4f d1 43 8d 0c 01 0f af c1 0f be d2 69 d2 ?? ?? ?? ?? 48 63 ca 48 69 c9}  //weight: 20, accuracy: Low
        $x_20_2 = {0f 4f d0 45 8d 04 09 48 83 c1 ?? 41 0f af c0 0f be d2 69 d2 ?? ?? ?? ?? 4c 63 c2 c1 fa 1f 4d 69 c0}  //weight: 20, accuracy: Low
        $x_10_3 = {45 8d 50 fc 41 8d 40 e0 41 80 f8 ?? 41 0f 4d c2 66 98 66 42 89 44 4a fe 49 8d 41 01 44 0f b6 44 01 ff 45 84 c0 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Rozena_SXA_2147959070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.SXA!MTB"
        threat_id = "2147959070"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {48 01 f6 48 01 de 42 0f b7 04 36 48 8d 04 83 42 8b 04 28 48 01 d8 eb 04}  //weight: 20, accuracy: High
        $x_10_2 = {44 8a 04 01 45 84 c0 74 1d 45 8d 48 e0 41 80 f8 59 7e 04 45 8d 48 fc 66 45 0f be c9 66 44 89 0c 42 48 ff c0 eb da}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rozena_YAI_2147959687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rozena.YAI!MTB"
        threat_id = "2147959687"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 10 8b 45 20 41 89 c0 8b 45 fc 48 63 c8 48 8b 45 10 48 01 c8 44 31 c2 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

