rule Trojan_Win32_GuLoader_AM_2147754207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.AM!MTB"
        threat_id = "2147754207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 cb d9 d0 [0-8] 75 50 00 4a [0-21] 29 db [0-21] 0b 1a [0-32] 39 cb d9 d0 [0-8] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {46 85 ff 8b 0f [0-8] 0f 6e c6 [0-8] 0f 6e c9 [0-8] 0f ef c8 [0-8] 0f 7e c9 [0-8] 39 c1 [0-8] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_GS_2147761303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.GS!MTB"
        threat_id = "2147761303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Informationsmaterialernes" wide //weight: 1
        $x_1_2 = "CURIOLOGICALLY" wide //weight: 1
        $x_1_3 = "HYPERPITUITARY" wide //weight: 1
        $x_1_4 = "Litteratursoegningsproces9" wide //weight: 1
        $x_1_5 = "prdikatomdbningerne" wide //weight: 1
        $x_1_6 = "sygesikringskontors" wide //weight: 1
        $x_1_7 = "Philosophicojuristic" wide //weight: 1
        $x_1_8 = "Elektrosvejsningen" wide //weight: 1
        $x_1_9 = "TOLVAARSFDSELSDAGENES" wide //weight: 1
        $x_1_10 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RG_2147775679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RG!MTB"
        threat_id = "2147775679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "slvbrylluppets" ascii //weight: 1
        $x_1_2 = "Antikvitetsforretninger2" ascii //weight: 1
        $x_1_3 = "Amfibietank" ascii //weight: 1
        $x_1_4 = "FLuxOil" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RG_2147775679_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RG!MTB"
        threat_id = "2147775679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Urinvejssygdommenes.Sig" ascii //weight: 1
        $x_1_2 = "Uninstall\\Eliderede" ascii //weight: 1
        $x_1_3 = "Ablatives\\Eyesight.ini" ascii //weight: 1
        $x_1_4 = "Software\\Spionkameraet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_BY_2147786317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.BY!MTB"
        threat_id = "2147786317"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Reguleringstillggene\\Blindedly\\Rumflyvningen" wide //weight: 1
        $x_1_2 = "Aided\\Hierurgical.Bic157" wide //weight: 1
        $x_1_3 = "Afstandes\\Transbaikal183\\pastichers\\Udsvejfningens.ini" wide //weight: 1
        $x_1_4 = "Coranto\\Centralbankchef.ini" wide //weight: 1
        $x_1_5 = "TEMP\\Reguleringstillggene\\Blindedly\\Rumflyvningen" wide //weight: 1
        $x_1_6 = "Svveflyet.unp" wide //weight: 1
        $x_1_7 = "Enneastylar\\Genoptagelse\\Vasoconstriction.ini" wide //weight: 1
        $x_1_8 = "Software\\Raghouse\\Geniusens\\Dorsal\\signatarmagterne" wide //weight: 1
        $x_1_9 = "Templates\\Enneastylar\\Genoptagelse\\Vasoconstriction.ini" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SIBB_2147794487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SIBB!MTB"
        threat_id = "2147794487"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 00 10 00 00 [0-32] ff 30 [0-32] 5b [0-32] [0-32] 39 fb 2d 00 10 00 00 [0-32] ff 30 [0-32] 5b [0-32] [0-32] 39 fb 75 ?? [0-32] b9 ?? ?? ?? ?? [0-32] 81 f1 ?? ?? ?? ?? [0-32] 81 f1 ?? ?? ?? ?? [0-32] 81 f1 ?? ?? ?? ?? [0-32] [0-32] 01 c8 [0-32] 8b 00 [0-32] b9 ?? ?? ?? ?? [0-32] 81 c1 ?? ?? ?? ?? [0-32] 81 f1 ?? ?? ?? ?? [0-32] 81 c1 ?? ?? ?? ?? [0-32] 51 [0-32] b9 ?? ?? ?? ?? [0-32] 81 c1 ?? ?? ?? ?? [0-32] [0-32] 81 e9 ?? ?? ?? ?? [0-32] 81 f1 ?? ?? ?? ?? [0-32] 51 [0-32] 68 ?? ?? ?? ?? [0-32] 31 c9 [0-32] [0-32] 51 [0-32] ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {83 f9 00 0f 85 ?? ?? ?? ?? [0-32] 8b 1c 0e [0-32] 89 1c 08 [0-32] bb ?? ?? ?? ?? [0-32] 31 ff [0-32] c7 45 ?? ?? ?? ?? ?? [0-32] 50 [0-32] 5a [0-32] 01 fa [0-32] 8b 32 [0-32] 31 de [0-32] c7 02 ?? ?? ?? ?? [0-32] 01 32 [0-32] 47 [0-32] 47 [0-32] 47 [0-32] [0-32] 47 [0-32] 3b 7d 08 0f 85 ?? ?? ?? ?? [0-32] ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_GuLoader_SIBC_2147794488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SIBC!MTB"
        threat_id = "2147794488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 2c 17 66 [0-32] [0-32] [0-32] 81 f5 ?? ?? ?? ?? [0-32] [0-32] [0-32] 01 2c 16 [0-32] [0-32] [0-32] 83 da 04 0f 8d ?? ?? ?? ?? [0-32] [0-32] [0-32] ff e6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SIBD_2147794799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SIBD!MTB"
        threat_id = "2147794799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d3 3d e5 [0-16] be ?? ?? ?? ?? [0-16] b9 ?? ?? ?? ?? [0-16] bf ?? ?? ?? ?? [0-16] 31 d2 [0-16] 33 14 0e [0-16] 09 14 08 [0-16] 31 3c 08 [0-16] 81 e9 ?? ?? ?? ?? [0-16] 81 c1 ?? ?? ?? ?? [0-16] 41 7d ?? [0-16] ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SIBE_2147794889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SIBE!MTB"
        threat_id = "2147794889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 08 9c 9d [0-32] 83 c0 ff [0-32] 39 08 9c 9d 75 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-240] 8b 1c 18 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-240] 50 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-240] 50 [0-32] 68 ?? ?? ?? ?? [0-32] 31 c0 [0-32] 50 [0-32] ff d3 [0-32] be ?? ?? ?? ?? [0-32] b9 ?? ?? ?? ?? [0-32] bf ?? ?? ?? ?? [0-32] 31 d2 [0-32] 33 14 0e [0-32] 09 14 08 [0-32] 31 3c 08 [0-32] 81 e9 ?? ?? ?? ?? [0-32] 81 c1 ?? ?? ?? ?? [0-32] 41 7d ?? [0-32] ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SIBF_2147794940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SIBF!MTB"
        threat_id = "2147794940"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f9 00 0f 85 ?? ?? ?? ?? [0-32] 8b 1c 0e [0-32] 89 1c 08 [0-32] bb ?? ?? ?? ?? [0-32] c7 45 ?? ?? ?? ?? ?? [0-32] c7 45 ?? ?? ?? ?? ?? [0-32] 50 [0-32] 5a [0-32] 03 55 06 [0-32] 8b 3a [0-32] 31 df [0-32] c7 02 ?? ?? ?? ?? [0-32] 01 3a [0-32] ff 45 06 [0-32] ff 45 06 [0-32] ff 45 06 [0-32] [0-32] ff 45 06 [0-32] 8b 7d 06 [0-32] 3b 7d 0a 0f 85 ?? ?? ?? ?? [0-32] ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RPK_2147796658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RPK!MTB"
        threat_id = "2147796658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f ae f0 81 f5 [0-16] 55 [0-16] 59 [0-16] 89 0c 37 [0-16] 4e [0-16] 4e [0-16] 4e [0-16] 4e 7d [0-16] 89 f9 [0-16] 51 [0-16] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RPK_2147796658_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RPK!MTB"
        threat_id = "2147796658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 2c 17 f7 c3 [0-32] [0-32] [0-16] 81 f5 [0-32] [0-32] [0-16] 01 2c 10 [0-32] [0-32] [0-32] [0-16] 83 da 04 [0-32] 0f 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RPF_2147798382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RPF!MTB"
        threat_id = "2147798382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 34 39 dd [0-16] [0-16] 01 34 3a [0-16] [0-16] 81 34 3a [0-16] [0-16] 83 ef [0-16] [0-16] 83 c7 [0-16] [0-16] 0f 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RPF_2147798382_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RPF!MTB"
        threat_id = "2147798382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 34 24 02 5c 4a ba [0-16] [0-16] [0-16] 8f 04 30 [0-16] [0-16] [0-16] [0-16] 83 de 28 [0-16] [0-16] 83 d6 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RPA_2147799546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RPA!MTB"
        threat_id = "2147799546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TRICROTIC1" ascii //weight: 1
        $x_1_2 = "MULTIKANAL1" ascii //weight: 1
        $x_1_3 = "Clinchers1" ascii //weight: 1
        $x_1_4 = "Ligningskommissioner1" ascii //weight: 1
        $x_1_5 = "AFREAGERINGERNES1" ascii //weight: 1
        $x_1_6 = "230202021837Z0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RPA_2147799546_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RPA!MTB"
        threat_id = "2147799546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 34 32 0f [0-16] [0-16] [0-16] [0-16] 81 34 24 [0-16] [0-16] [0-16] [0-16] 8f 04 30 [0-16] [0-16] [0-32] [0-16] [0-16] 83 de [0-16] [0-16] [0-16] 83 d6 [0-16] [0-16] 0f 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RPA_2147799546_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RPA!MTB"
        threat_id = "2147799546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Smittekilderne51.lnk" wide //weight: 1
        $x_1_2 = "forbedringshuses.SYM" wide //weight: 1
        $x_1_3 = "metageometer" wide //weight: 1
        $x_1_4 = "LRERROLLER.ANS" wide //weight: 1
        $x_1_5 = "Software\\Sisiutl169\\Jesuiterordnens157" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RPB_2147799547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RPB!MTB"
        threat_id = "2147799547"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 34 39 d9 [0-16] [0-16] 01 34 3a [0-16] [0-16] 81 34 3a [0-16] [0-16] 83 ef [0-16] [0-16] 83 c7 [0-16] [0-16] 0f 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RPC_2147799548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RPC!MTB"
        threat_id = "2147799548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c1 00 8b 34 39 [0-16] [0-16] 01 34 3a [0-16] [0-16] 81 34 3a [0-16] [0-16] 83 ef [0-16] [0-16] 83 c7 [0-16] [0-16] 0f 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RPC_2147799548_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RPC!MTB"
        threat_id = "2147799548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 04 13 9b 90 9b 9b d9 ea d9 c9 d9 e4 0f dc ef}  //weight: 1, accuracy: High
        $x_1_2 = {81 fb c8 00 00 00 83 f9 17 01 34 08 83 f9 0c 0f 73 f7 61 0f db f1}  //weight: 1, accuracy: High
        $x_1_3 = {09 04 31 90 66 0f eb cc eb 3e 9f 91 2d 75 31 31 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_GuLoader_RPE_2147805176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RPE!MTB"
        threat_id = "2147805176"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 1c 3a 83 [0-16] 81 f3 [0-16] 09 1c 38 [0-16] 83 ef [0-16] 81 ff [0-16] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RPG_2147805177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RPG!MTB"
        threat_id = "2147805177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 1c 3a 83 [0-16] 81 f3 [0-16] 09 1c 38 [0-16] 83 ef [0-16] 81 ff [0-16] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SIBM_2147805726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SIBM!MTB"
        threat_id = "2147805726"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Esothyropexy4" ascii //weight: 1
        $x_1_2 = {56 f8 31 ff [0-4] 57 [0-5] ff d0 [0-8] e8 ?? ?? ?? ?? [0-8] 31 ff [0-16] bb ?? ?? ?? ?? [0-8] 81 f3 ?? ?? ?? ?? [0-48] 0b 1c 3a [0-8] 81 f3 ?? ?? ?? ?? [0-8] 09 1c 38 [0-10] 83 c7 04 [0-5] 81 ff ?? ?? ?? ?? 75 ?? [0-7] ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SIBP_2147805727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SIBP!MTB"
        threat_id = "2147805727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Nulkomponent" ascii //weight: 1
        $x_1_2 = {83 c7 04 83 34 24 ?? 81 ff ?? ?? ?? ?? [0-10] bb ?? ?? ?? ?? [0-10] 81 c3 ?? ?? ?? ?? [0-16] 81 f3 ?? ?? ?? ?? [0-10] 81 c3 ?? ?? ?? ?? [0-16] 0b 1c 3a [0-10] 81 f3 ?? ?? ?? ?? [0-10] 09 1c 38 [0-10] 83 c7 04 83 34 24 ?? 81 ff 01 0f 85 ?? ?? ?? ?? [0-5] ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_AD_2147805942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.AD!MTB"
        threat_id = "2147805942"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rot13.dll" wide //weight: 1
        $x_1_2 = "crookeder.ini" wide //weight: 1
        $x_1_3 = "SearchTreeForFile(t 'LIMBOUS',t 'Hotspot',m 'FAINTLY')" wide //weight: 1
        $x_1_4 = "wigwams.ini" wide //weight: 1
        $x_1_5 = "fuzzer.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_AD_2147805942_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.AD!MTB"
        threat_id = "2147805942"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fzshellext.dll" wide //weight: 1
        $x_1_2 = "Eddie-Service-Elevated.exe" wide //weight: 1
        $x_1_3 = "MpCmdRun.exe" wide //weight: 1
        $x_1_4 = "CoverEdCtrl.manifest" wide //weight: 1
        $x_1_5 = "PSReadline.ps" wide //weight: 1
        $x_1_6 = "PanelInfo.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_AD_2147805942_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.AD!MTB"
        threat_id = "2147805942"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "FYNBOENACCID" ascii //weight: 3
        $x_3_2 = "polypsyc" ascii //weight: 3
        $x_3_3 = "brndesk" ascii //weight: 3
        $x_3_4 = "Baandoptagereshar" ascii //weight: 3
        $x_3_5 = "Uskadeliggrelsern" ascii //weight: 3
        $x_3_6 = "Squirme" ascii //weight: 3
        $x_3_7 = "EVENT_SINK_AddRef" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_AD_2147805942_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.AD!MTB"
        threat_id = "2147805942"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "fllesbrn.txt" ascii //weight: 2
        $x_2_2 = "Yderredens102.Kan" ascii //weight: 2
        $x_2_3 = "blinkenberg.txt" ascii //weight: 2
        $x_2_4 = "civilisable\\Enterococci143" ascii //weight: 2
        $x_2_5 = "mesalliancers\\Seksaaringen" ascii //weight: 2
        $x_2_6 = "chego\\reverensens" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_QW_2147807411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.QW!MTB"
        threat_id = "2147807411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "HOMOCHROMIC" ascii //weight: 3
        $x_3_2 = "Scripting.FileSystemObject" ascii //weight: 3
        $x_3_3 = "kilowattenes" ascii //weight: 3
        $x_3_4 = "windir" ascii //weight: 3
        $x_3_5 = "\\flKknkUR6B3JMPQjtG45" ascii //weight: 3
        $x_3_6 = "FolderExists" ascii //weight: 3
        $x_3_7 = "Feathertop" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_MB_2147812754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.MB!MTB"
        threat_id = "2147812754"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "chlamyses" ascii //weight: 3
        $x_3_2 = "arresterende" ascii //weight: 3
        $x_3_3 = "RNEBLIKS" ascii //weight: 3
        $x_3_4 = "Za-Verizon" ascii //weight: 3
        $x_3_5 = "CreateTextFile" ascii //weight: 3
        $x_3_6 = "Scripting.FileSystemObject" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_MB_2147812754_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.MB!MTB"
        threat_id = "2147812754"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetDiskFreeSpaceW" ascii //weight: 1
        $x_1_2 = "FOLKEBIBLIOTEKER" wide //weight: 1
        $x_1_3 = "Vrdisikret214" wide //weight: 1
        $x_1_4 = "REASSUREDLY" wide //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\LAICIZED" wide //weight: 1
        $x_1_6 = "Dinosaurusserne7" wide //weight: 1
        $x_1_7 = "Software\\STAFFSTRIKER\\recrop" wide //weight: 1
        $x_1_8 = "Software\\ligestillingerne\\IMPUTRESCENCE" wide //weight: 1
        $x_1_9 = "Software\\forbandelses\\vgges" wide //weight: 1
        $x_1_10 = "\\MUSSULMANISH.ini" wide //weight: 1
        $x_1_11 = "Software\\UNDIRECTLY\\indirect" wide //weight: 1
        $x_1_12 = "STATIONSINDSTILLINGEN" wide //weight: 1
        $x_1_13 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sensibiliserende" wide //weight: 1
        $x_1_14 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Aerodynamic" wide //weight: 1
        $x_1_15 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\URKOKKENE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_MA_2147813002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.MA!MTB"
        threat_id = "2147813002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {af df 26 be c0 dd 44 8c 78 b6 d8 f9 54 62 21}  //weight: 1, accuracy: High
        $x_1_2 = {c4 29 04 03 00 00 00 00 ff cc 31 00 2b b2 2f de ca ed 8e 79 46 9a ec 92 ce c7 a6 62 c2 c9 cb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_MA_2147813002_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.MA!MTB"
        threat_id = "2147813002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "C:\\Windows\\explorer.EXE\" C:\\windows\\system32\\svchost.exe" wide //weight: 3
        $x_3_2 = "Uninstall\\PDF_Reader" ascii //weight: 3
        $x_3_3 = "CreateFileMappingA(i r5, i 0, i 0x40, i 0, i 0, i 0)i.r4" ascii //weight: 3
        $x_3_4 = "vbsedit.txt" ascii //weight: 3
        $x_3_5 = "SetSecurityDescriptorDacl" ascii //weight: 3
        $x_3_6 = "ExecToLog" ascii //weight: 3
        $x_3_7 = "ShellExecuteExW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_MC_2147813003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.MC!MTB"
        threat_id = "2147813003"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "beam_r.cur" ascii //weight: 3
        $x_3_2 = "beam_rl.cur" ascii //weight: 3
        $x_3_3 = "busy.svg" ascii //weight: 3
        $x_3_4 = "system.ini" ascii //weight: 3
        $x_3_5 = "\\something.ini" ascii //weight: 3
        $x_3_6 = "kernel32.dll::RtlMoveMemory(*i r3 r3,i r9,i 4)" ascii //weight: 3
        $x_3_7 = "Concuit" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_MC_2147813003_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.MC!MTB"
        threat_id = "2147813003"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AsGenIcon.pdb" ascii //weight: 1
        $x_1_2 = "CreateMutexW" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "KillTimer" ascii //weight: 1
        $x_1_5 = "\\FRILAGDE\\SKRMYDSELS" wide //weight: 1
        $x_1_6 = "Software\\POSTAGES\\Naturfags" wide //weight: 1
        $x_1_7 = "\\Rentekompensationen.DIB" wide //weight: 1
        $x_1_8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\KAPITLERS" wide //weight: 1
        $x_1_9 = "Software\\Baddishness94\\WOORARIS" wide //weight: 1
        $x_1_10 = "Software\\Maskinordets\\KANARA" wide //weight: 1
        $x_1_11 = "\\SVOVLBLAAT.uni" wide //weight: 1
        $x_1_12 = "Software\\Volcanus\\TEOLOGISKES" wide //weight: 1
        $x_1_13 = "Software\\arterioscleroses\\Tegnstningens63" wide //weight: 1
        $x_1_14 = "Software\\Tandfrembrud132\\MORMONSKES" wide //weight: 1
        $x_1_15 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\SLANDEROUS" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_MD_2147813004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.MD!MTB"
        threat_id = "2147813004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 4f 01 8a 07 8a d1 8a d8 83 e2 7f 83 e3 7f c1 e2 07 0f b6 c0 0b d3 8b d8 89 55 f8}  //weight: 10, accuracy: High
        $x_3_2 = "C:\\Windows\\explorer.EXE\" C:\\windows\\system32\\hh.exe" wide //weight: 3
        $x_3_3 = "pidgin.exe" ascii //weight: 3
        $x_3_4 = "readme.txt" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_MD_2147813004_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.MD!MTB"
        threat_id = "2147813004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Predeceived.dll" ascii //weight: 1
        $x_1_2 = "Mosehusets94" wide //weight: 1
        $x_1_3 = "Gennembrydende Daubry.exe" wide //weight: 1
        $x_1_4 = "Windows\\CurrentVersion\\Uninstall\\Spontanisternes54\\Konsistensernes\\Sanktionsfaststtelser" ascii //weight: 1
        $x_1_5 = "Software\\Driftsbygningen\\Polycitral" ascii //weight: 1
        $x_1_6 = "Software\\Garantibetalingernes\\Hygienise" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_M_2147813007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.M!MTB"
        threat_id = "2147813007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Windows\\explorer.EXE\" C:\\windows\\system32\\svchost.exe" wide //weight: 3
        $x_3_2 = "Uninstall\\PDF_Reader" ascii //weight: 3
        $x_3_3 = "InitiateShutdownW" ascii //weight: 3
        $x_3_4 = "Simple.png" ascii //weight: 3
        $x_3_5 = "SimpleColor.dll" ascii //weight: 3
        $x_3_6 = "CreateFileMappingW(i r2, i 0, i 0x40, i 0, i 0, i 0)i.r3" ascii //weight: 3
        $x_3_7 = "Classic.png" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_N_2147813016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.N!MTB"
        threat_id = "2147813016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Schick" ascii //weight: 3
        $x_3_2 = "Decolorising6.dat" ascii //weight: 3
        $x_3_3 = "rottedes" ascii //weight: 3
        $x_3_4 = "slwga" ascii //weight: 3
        $x_3_5 = "Security-SPP-GenuineLocalStatus" ascii //weight: 3
        $x_3_6 = "NtQuerySystemInformation" ascii //weight: 3
        $x_3_7 = "EtwEventEnabled" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_NA_2147813311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.NA!MTB"
        threat_id = "2147813311"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "English.tips" ascii //weight: 3
        $x_3_2 = "MDT2DFX.DLL" ascii //weight: 3
        $x_3_3 = "(i 0,i 0x100000, i 0x3000, i 0x40)p.r3" ascii //weight: 3
        $x_3_4 = "CommonFilesDir" ascii //weight: 3
        $x_3_5 = "C:\\Program Files" ascii //weight: 3
        $x_3_6 = "COPYING.txt" ascii //weight: 3
        $x_3_7 = "wininit.ini" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SIBU_2147813441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SIBU!MTB"
        threat_id = "2147813441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Coventries Setup: Installing" ascii //weight: 1
        $x_1_2 = {aa 81 34 1a ?? ?? ?? ?? [0-64] 43 [0-58] 43 [0-64] 43 [0-48] 43 [0-42] 81 fb ?? ?? ?? ?? [0-48] 0f 85 ?? ?? ?? ?? [0-58] bc 01 ff d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SIBU1_2147813442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SIBU1!MTB"
        threat_id = "2147813442"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOLDIERING Setup: Installing" ascii //weight: 1
        $x_1_2 = {f9 81 34 1a ?? ?? ?? ?? [0-53] 43 [0-48] 43 [0-58] 43 [0-48] 43 [0-58] 81 fb ?? ?? ?? ?? [0-64] 0f 85 ?? ?? ?? ?? 3a 01 81 36 ?? ?? ?? ?? [0-64] 81 2e ?? ?? ?? ?? [0-58] ff d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SIBU2_2147813444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SIBU2!MTB"
        threat_id = "2147813444"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " Setup: Installing" ascii //weight: 1
        $x_1_2 = {bb 81 34 1a ?? ?? ?? ?? [0-58] 43 [0-53] 43 [0-53] 43 [0-58] 43 [0-42] 81 fb ?? ?? ?? ?? [0-48] 0f 85 ?? ?? ?? ?? 52 01 81 36 ?? ?? ?? ?? [0-129] 36 ?? ?? ?? ?? [0-255] d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SIBU3_2147813521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SIBU3!MTB"
        threat_id = "2147813521"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GiantDock" ascii //weight: 1
        $x_1_2 = {89 d3 c1 e2 ?? [0-5] 01 da 0f b6 1e 53 [0-10] 01 da 81 f2 ?? ?? ?? ?? 83 c6 02 [0-10] 66 8b 1e 66 83 fb 00 [0-10] 75}  //weight: 1, accuracy: Low
        $x_1_3 = {38 06 8b 85 ?? ?? ?? ?? 73 ?? 89 c3 [0-5] c1 e0 ?? 01 d8 0f b6 0e 01 c8 35 ?? ?? ?? ?? 46 88 95 ?? ?? ?? ?? [0-5] 8a 16 [0-5] 80 fa 00 8a 95 06 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SIBU17_2147814364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SIBU17!MTB"
        threat_id = "2147814364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "unknowndll.pdb" ascii //weight: 1
        $x_1_2 = {ff 34 0f d9 ?? ?? ?? ?? [0-106] 31 04 24 [0-100] 8f 04 0f [0-108] 83 c1 04 [0-80] 81 f9 ?? ?? ?? ?? [0-64] 0f 85 ?? ?? ?? ?? [0-176] ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SIBU18_2147814365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SIBU18!MTB"
        threat_id = "2147814365"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "unknowndll.pdb" ascii //weight: 1
        $x_1_2 = {ff 34 0f d9 ?? ?? ?? ?? [0-106] 31 04 24 [0-106] 8f 04 0f [0-122] 83 c1 04 [0-85] 81 f9 ?? ?? ?? ?? [0-58] 0f 85 ?? ?? ?? ?? [0-106] 57 [0-112] ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_EM_2147815017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.EM!MTB"
        threat_id = "2147815017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {81 e3 de d1 00 00 5b 81 ea 19 f5 00 00 41 35 82 18 00 00 43 81 f9 c2 b4 00 00 74 14 48 f7 d2 81 ea 13 54 01 00 b9 f8 7e 01 00 81 e2 10 03 00 00 05 c9 0d}  //weight: 5, accuracy: High
        $x_5_2 = {8b 47 3c 33 f6 8b 44 38 78 03 c7 8b 48 24 8b 50 20 03 cf 89 4d f8 03 d7 8b 48 1c 03 cf 89 55 fc 89 4d f4 8b 48 18 89 4d 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_EM_2147815017_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.EM!MTB"
        threat_id = "2147815017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "unhailed\\Bygrnsernes.lnk" ascii //weight: 1
        $x_1_2 = "Boilermaker129.sag" ascii //weight: 1
        $x_1_3 = "brdfrugttrers\\reggio.ini" ascii //weight: 1
        $x_1_4 = "blommestenenes\\upflows.ini" ascii //weight: 1
        $x_1_5 = "nulpunktsgennemgange\\claywares\\Pagedom" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_EM_2147815017_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.EM!MTB"
        threat_id = "2147815017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Krftsvulsterne" wide //weight: 1
        $x_1_2 = "Opdrttet37.Ved" wide //weight: 1
        $x_1_3 = "Chimeric\\Rabiates" wide //weight: 1
        $x_1_4 = "minidump-analyzer.exe" wide //weight: 1
        $x_1_5 = "Siphonostomatous\\Horneddevil.Bil" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_CB_2147815723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.CB!MTB"
        threat_id = "2147815723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "blamability.dat" ascii //weight: 3
        $x_3_2 = "wsock32::gethostbyname(t 'Bisymmetric247')" ascii //weight: 3
        $x_3_3 = "user32::GetKeyboardType(i 249)" ascii //weight: 3
        $x_3_4 = "kernel32::SetComputerNameA(t 'artisternes')" ascii //weight: 3
        $x_3_5 = "Software\\aflbsbrndenes\\Orexis" ascii //weight: 3
        $x_3_6 = "DllUnregisterServer" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_CB_2147815723_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.CB!MTB"
        threat_id = "2147815723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Pruritus\\Unhuskable\\Opgrelser.Sty" ascii //weight: 1
        $x_1_2 = "Sangeres\\Tredveaarsdages\\Automatteorien.ini" ascii //weight: 1
        $x_1_3 = "Besvrliggrelserne\\Pixiness.Inv" ascii //weight: 1
        $x_1_4 = "Alumin\\Studieglds\\Statsamternes\\Nonegregiousness.ini" ascii //weight: 1
        $x_1_5 = "Nringsmaterialernes229.ini" ascii //weight: 1
        $x_1_6 = "Skibsvrftets\\Featherfoil.ini" ascii //weight: 1
        $x_1_7 = "Harmoniserings\\Compassment3.lnk" ascii //weight: 1
        $x_1_8 = "Panthea\\Binoculars\\afslutningens\\Handelshindringerne.Unf141" ascii //weight: 1
        $x_1_9 = "Unmullioned\\Uanmeldte\\Nordamerikansk\\Knogleledets.ini" ascii //weight: 1
        $x_1_10 = "rkkehusets\\Nyttet\\Galoping.Kno" ascii //weight: 1
        $x_1_11 = "Blreroden\\Kernereaktorens.dll" ascii //weight: 1
        $x_1_12 = "Pureen\\Netti\\Pyloralgia.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_GuLoader_AH_2147816513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.AH!MTB"
        threat_id = "2147816513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "process-stop-symbolic.svg" wide //weight: 3
        $x_3_2 = "tab-new-symbolic.symbolic.png" wide //weight: 3
        $x_3_3 = "view-refresh-symbolic.symbolic.png" wide //weight: 3
        $x_3_4 = "user32::FindWindowA(t 'snustobakker',t 'Funktionsforskrifter')" wide //weight: 3
        $x_3_5 = "KERNEL32::ReadFile(i R6, i R5, i 0x100000,*i 0, i 0)" wide //weight: 3
        $x_3_6 = "gdi32::AbortPath (i 0)i.r9" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_AH_2147816513_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.AH!MTB"
        threat_id = "2147816513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "skrivebetegnelserne\\Kalkulationskolonner62.Und" wide //weight: 1
        $x_1_2 = "Overdazzling.ini" wide //weight: 1
        $x_1_3 = "Sortimentsboghandels" wide //weight: 1
        $x_1_4 = "Kalkulationskolonner62.Und" wide //weight: 1
        $x_1_5 = "Fremmedordbog" wide //weight: 1
        $x_1_6 = "Plight\\Canonist\\Hastener\\Robbins.Afs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_XTW_2147816561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.XTW!MTB"
        threat_id = "2147816561"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7d 03 55 40 [0-10] 60 e4 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 3a d9 f6 [0-9] eb}  //weight: 1, accuracy: Low
        $x_1_3 = {31 df de f7 [0-9] eb}  //weight: 1, accuracy: Low
        $x_1_4 = {01 3a 66 0f [0-10] eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SIBW_2147816657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SIBW!MTB"
        threat_id = "2147816657"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "bakteriologierne" wide //weight: 1
        $x_1_2 = "\\Twichild172\\Telegrafers67" wide //weight: 1
        $x_1_3 = "occtaux.dll" wide //weight: 1
        $x_1_4 = "\\terp.dat" wide //weight: 1
        $x_1_5 = {1b 7a a2 e2 ?? b9 ?? ?? ?? ?? 29 f0 1f 72 ?? 5f 9f ee 38 b3 ?? ?? ?? ?? 65 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SIBV1_2147816735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SIBV1!MTB"
        threat_id = "2147816735"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Epin EiDIa ila" wide //weight: 1
        $x_1_2 = "ARiCle AFRporaToon" wide //weight: 1
        $x_1_3 = {83 c6 01 66 [0-10] ff 37 [0-10] 31 34 24 [0-10] 5b [0-10] 3b 5c 24 ?? 75 ?? [0-10] bb ?? ?? ?? ?? [0-10] 83 eb 04 [0-10] ff 34 1f [0-10] 5a [0-10] e8 ?? ?? ?? ?? [0-10] 09 14 18 [0-10] 75 ?? [0-10] ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SIBM1_2147816745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SIBM1!MTB"
        threat_id = "2147816745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "% P.I.C Program" wide //weight: 1
        $x_1_2 = "Zouave5" ascii //weight: 1
        $x_1_3 = {b8 00 00 00 00 [0-10] 50 [0-106] b8 ?? ?? ?? ?? [0-240] 01 c2 [0-106] ff 12 [0-112] ff 37 [0-10] 5d [0-106] 31 f5 [0-10] 31 2c 10 [0-106] 83 c2 04 [0-10] 83 c7 04 [0-106] 81 fa ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? [0-106] 50 [0-10] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SIBM2_2147816746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SIBM2!MTB"
        threat_id = "2147816746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 9d 81 34 17 ?? ?? ?? ?? [0-48] 83 c2 04 [0-48] 81 fa ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? [0-48] ff e7}  //weight: 1, accuracy: Low
        $x_1_2 = "Variantfunktions" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SIBM2_2147816746_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SIBM2!MTB"
        threat_id = "2147816746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Malcom" wide //weight: 1
        $x_1_2 = "7-Even UP" wide //weight: 1
        $x_1_3 = {83 e9 04 eb ?? ?? ?? ?? [0-74] 8b 99 ?? ?? ?? ?? [0-96] 33 5d ?? [0-48] 89 1c 08 [0-96] 83 e9 04 [0-74] 0f 8d ?? ?? ?? ?? [0-128] [0-192] 5b [0-133] 6a 00 [0-90] 6a 00 [0-138] 50 [0-112] 53 [0-106] 6a 00 [0-128] 6a 00 [0-32] ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SIBM3_2147817234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SIBM3!MTB"
        threat_id = "2147817234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "PARALLELIZING" wide //weight: 1
        $x_1_2 = {e0 81 34 17 ?? ?? ?? ?? [0-48] 83 c2 04 [0-48] 81 fa ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? [0-48] ff e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SIBM12_2147817695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SIBM12!MTB"
        threat_id = "2147817695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 0c 03 66 5a 02 81 f1 ?? ?? ?? ?? 5a 02 89 0c 03 20 02 83 c0 04 10 02 3d ?? ?? ?? ?? [0-112] 0f 85 ?? ?? ?? ?? b0 01 ff d3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SIBM14_2147817740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SIBM14!MTB"
        threat_id = "2147817740"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0c 03 0f 70 01 80 f1 00 [0-170] 81 f1 ?? ?? ?? ?? 60 02 89 0c 03 c0 01 83 c0 04 aa 01 3d ?? ?? ?? ?? [0-96] 0f 85 ?? ?? ?? ?? ba 01 ff d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SIBM15_2147817752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SIBM15!MTB"
        threat_id = "2147817752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 d2 89 d2 [0-10] 81 ea ?? ?? ?? ?? [0-16] 81 f2 ?? ?? ?? ?? [0-64] 81 ea ?? ?? ?? ?? [0-32] 33 14 31 [0-16] 81 f2 ?? ?? ?? ?? [0-64] 8b 1c 24 [0-10] 01 14 33 [0-16] 83 ee 04 0f 8d ?? ?? ?? ?? [0-10] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SIBM16_2147818081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SIBM16!MTB"
        threat_id = "2147818081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "bondship" wide //weight: 1
        $x_1_2 = {83 c2 04 80 [0-48] 81 fa ?? ?? ?? ?? [0-48] 81 34 17 ?? ?? ?? ?? [0-48] 83 c2 04 [0-48] 81 fa ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? [0-48] ff e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_DA_2147821134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.DA!MTB"
        threat_id = "2147821134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "isbjergets\\brandinspektrerne\\regnens" ascii //weight: 1
        $x_1_2 = "Laurbrkransene.pri" ascii //weight: 1
        $x_1_3 = "Svelningers.ini" ascii //weight: 1
        $x_1_4 = "opfrelses\\tippelad\\generalinders" ascii //weight: 1
        $x_1_5 = "germayne.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_DA_2147821134_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.DA!MTB"
        threat_id = "2147821134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uninvadable.exe" wide //weight: 1
        $x_1_2 = "Energising.bin" wide //weight: 1
        $x_1_3 = "Superevidence.ini" wide //weight: 1
        $x_1_4 = "Eddie-CLI.exe" wide //weight: 1
        $x_1_5 = "Hderkronet237.lnk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_GuLoader_DA_2147821134_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.DA!MTB"
        threat_id = "2147821134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "distensile prettiness declaratives" ascii //weight: 10
        $x_10_2 = "affaldsbehandlingssystem" ascii //weight: 10
        $x_10_3 = "carlot virginia omskriver" ascii //weight: 10
        $x_10_4 = "\\Knoxvillite\\Loosened\\Afgaaet\\Trkkerens" ascii //weight: 10
        $x_10_5 = "Tilkendegivelsen Blebukser Snowbirds" ascii //weight: 10
        $x_10_6 = "gravitation kaolinized campulitropal" ascii //weight: 10
        $x_10_7 = "fejlvurderet zoofili paraglossa" ascii //weight: 10
        $x_10_8 = "sammentrknings samlelinser" ascii //weight: 10
        $x_10_9 = "gaussfunktionernes misreckoning" ascii //weight: 10
        $x_1_10 = "moulage indlgningerne poltroonish" ascii //weight: 1
        $x_1_11 = "appliance slagging pollyanna" ascii //weight: 1
        $x_1_12 = "kubikindholdet abacate generindrer" ascii //weight: 1
        $x_1_13 = "\\Recostumed\\Nikkelheftedes" ascii //weight: 1
        $x_1_14 = "Konfiskerede" ascii //weight: 1
        $x_1_15 = "inaccuracy gascon indeslutningers" ascii //weight: 1
        $x_1_16 = "blokniveauernes unavngivet" ascii //weight: 1
        $x_1_17 = "beregneliges" ascii //weight: 1
        $x_1_18 = "bundafstandenes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_GuLoader_BM_2147821231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.BM!MTB"
        threat_id = "2147821231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Forbogstav.lnk" wide //weight: 1
        $x_1_2 = "Copy Details To Clipboard" wide //weight: 1
        $x_1_3 = "*.scu" wide //weight: 1
        $x_1_4 = "BULLNECK" wide //weight: 1
        $x_1_5 = "bulkladninger" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RPD_2147825089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RPD!MTB"
        threat_id = "2147825089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8f 04 30 d9 f3 de c8 eb 42 0a 45 d7 54 85 85 85 85 85 85}  //weight: 1, accuracy: High
        $x_1_2 = {84 db 31 1c 08 84 db 83 c1 04 d9 e8 eb 51 be 9d e5 65 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_GuLoader_EL_2147826452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.EL!MTB"
        threat_id = "2147826452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Slippes2.lnk" ascii //weight: 1
        $x_1_2 = "Bronchus" wide //weight: 1
        $x_1_3 = "PrintHood\\Bryologi\\*.Ter" wide //weight: 1
        $x_1_4 = "Opdateringssiderne166" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_EL_2147826452_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.EL!MTB"
        threat_id = "2147826452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lnkontos.Dew" ascii //weight: 1
        $x_1_2 = "thirdness\\Transphysical\\burhne.dll" ascii //weight: 1
        $x_1_3 = "Brugerordbog\\*.klt" wide //weight: 1
        $x_1_4 = "Teamworket32" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_AUM_2147826874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.AUM!MTB"
        threat_id = "2147826874"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Opsgningerne\\Historician8" wide //weight: 1
        $x_1_2 = "Software\\RAVIOLIEN\\Replicerede166" wide //weight: 1
        $x_1_3 = "bromoaurate.exe" wide //weight: 1
        $x_1_4 = "fossildelta.dll" wide //weight: 1
        $x_1_5 = "Putationary191.ini" wide //weight: 1
        $x_1_6 = "Skibstilsyn112.lnk" wide //weight: 1
        $x_1_7 = "Paasttelsens223.ini" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_AYC_2147826884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.AYC!MTB"
        threat_id = "2147826884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\BIRDWEED\\Afsvrgelser" wide //weight: 1
        $x_1_2 = "Software\\Suomis\\smregravens" wide //weight: 1
        $x_1_3 = "Ambassadrerne59.ini" wide //weight: 1
        $x_1_4 = "USERPROFILE\\Baandskifterne125.lnk" wide //weight: 1
        $x_1_5 = "Disgraced166.dll" wide //weight: 1
        $x_1_6 = "Fortrngningsmekanisme12.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_AYC_2147826884_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.AYC!MTB"
        threat_id = "2147826884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Snuedes9\\ALLOPATRICALLY\\Benmelsstop\\Pulsaarer1.dis" wide //weight: 1
        $x_1_2 = "Software\\Unopened\\GGESALATERNES\\Utilfredsheds\\Sprgsmaalstegn" wide //weight: 1
        $x_1_3 = "Sedimentology\\mesembryonic\\Parabranchiate" wide //weight: 1
        $x_1_4 = "Hulkindedes\\entomolog\\Windowshade.lnk" wide //weight: 1
        $x_1_5 = "Tiltuskninger56.Unb" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_AYB_2147827039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.AYB!MTB"
        threat_id = "2147827039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Kngtes\\Vrelsesanvisningerne" wide //weight: 1
        $x_1_2 = "Minuenden149\\Antisyphons\\Satiriker" wide //weight: 1
        $x_1_3 = "Hvidmale.ini" wide //weight: 1
        $x_1_4 = "Sjlehallen.lnk" wide //weight: 1
        $x_1_5 = "%WINDIR%\\Strbet\\Ravnemoderens\\Bryllupsnatten" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_BYG_2147827205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.BYG!MTB"
        threat_id = "2147827205"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bosnien\\Trivialiseringers.ini" wide //weight: 1
        $x_1_2 = "MASKINSTATIONEN.ini" wide //weight: 1
        $x_1_3 = "PrintHood\\Harmonikasammenstdet.dll" wide //weight: 1
        $x_1_4 = "Paniculitis233\\ungravelly\\Discretions" wide //weight: 1
        $x_1_5 = "Ungermane95\\Eliderendes\\Karosserierne" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_AYE_2147827644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.AYE!MTB"
        threat_id = "2147827644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Nonnecessitousness\\Classwork\\Stangen\\hummedes.dll" wide //weight: 1
        $x_1_2 = "Start Menu\\Devoices" wide //weight: 1
        $x_1_3 = "Uninstall\\Cerviciplex" ascii //weight: 1
        $x_1_4 = "Weathergleam\\Tidsskriftsbiblioteket.STY" ascii //weight: 1
        $x_1_5 = "Agedly\\BALISTRARIA\\Nudelsuppe.ini" ascii //weight: 1
        $x_1_6 = "Detektivarbejders\\Preaggravate\\Feoffee.und" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_ASM_2147833276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.ASM!MTB"
        threat_id = "2147833276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Exship59\\optrnende.dll" ascii //weight: 1
        $x_1_2 = "Baandskifternes\\protohistorian\\Knuses187" ascii //weight: 1
        $x_1_3 = "socialbegivenheden\\hallucinationers.dll" ascii //weight: 1
        $x_1_4 = "physophore\\straedet.ini" ascii //weight: 1
        $x_1_5 = "Gulvhjderne149\\helsilkes.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_DB_2147833650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.DB!MTB"
        threat_id = "2147833650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Finanslovforslagets\\Erholdelige" ascii //weight: 1
        $x_1_2 = "Skibsprovianteringshandlerens\\Klapstol\\Svenskekonger\\Aasmund.ini" ascii //weight: 1
        $x_1_3 = "Plovers\\Berigninger.Iar" ascii //weight: 1
        $x_1_4 = "Diskjockey\\Clavariaceae\\Spruciest\\Investeringspolitikken.Eat" ascii //weight: 1
        $x_1_5 = "Flugtsikreste\\Skabiosernes\\knystet\\Sfrers.Har" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_DD_2147833934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.DD!MTB"
        threat_id = "2147833934"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Afskrivningsmaadernes\\Nauticality207\\Droved151" wide //weight: 1
        $x_1_2 = "Stentorrsten\\Kolonier\\Explanative\\Gestor.Fat" wide //weight: 1
        $x_1_3 = "Noncontingently\\Besnrelserne.Bef" wide //weight: 1
        $x_1_4 = "Disguisay\\Gudemother86\\Njedes\\Superalbuminosis.ini" wide //weight: 1
        $x_1_5 = "Unmannishly\\Spotske.ini" wide //weight: 1
        $x_1_6 = "Merrytrotter\\Hao\\Galax\\Enkeltmandskredse" wide //weight: 1
        $x_1_7 = "pakkes\\Tilstningsstofs\\Quinologist" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RSM_2147839634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RSM!MTB"
        threat_id = "2147839634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Stater Bros. Holdings Inc." ascii //weight: 1
        $x_1_2 = "Viacom Inc" ascii //weight: 1
        $x_1_3 = "MeadWestvaco Corporation" ascii //weight: 1
        $x_1_4 = "kundebrevet.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RSM_2147839634_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RSM!MTB"
        threat_id = "2147839634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dreyer's Grand Ice Cream, Inc." ascii //weight: 1
        $x_1_2 = "Lennox International Inc." ascii //weight: 1
        $x_1_3 = "Kellogg Company" ascii //weight: 1
        $x_1_4 = "Barnes & Noble, Inc." ascii //weight: 1
        $x_1_5 = "invigilate havearkitekter.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_DE_2147841539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.DE!MTB"
        threat_id = "2147841539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Montricerne.Ben" ascii //weight: 1
        $x_1_2 = "Software\\Procentuelles232\\Frafaldsprocents\\Forarbejdendes\\Inceration" ascii //weight: 1
        $x_1_3 = "Kommunikationsfirmaet\\Gldstningers.ini" ascii //weight: 1
        $x_1_4 = "Intercalm\\Kommunikationsteknisk\\Shauling\\Stddmpers.Non" ascii //weight: 1
        $x_1_5 = "Vederheftigheden\\Medeas\\Malignment\\Cullionry" ascii //weight: 1
        $x_1_6 = "ejdendes\\Inceration" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RSP_2147845437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RSP!MTB"
        threat_id = "2147845437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Koreograferendes" wide //weight: 1
        $x_1_2 = "Kaliberbor" wide //weight: 1
        $x_1_3 = "Software\\Vekslendes" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RSP_2147845437_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RSP!MTB"
        threat_id = "2147845437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\unproselyte\\besparelses" ascii //weight: 1
        $x_1_2 = "6\\Prefigure.emu" ascii //weight: 1
        $x_1_3 = "\\stemmespildskampagnes.una" ascii //weight: 1
        $x_1_4 = "entitle vrdifuldes anale" ascii //weight: 1
        $x_1_5 = "bishoprics stalagmitterne" ascii //weight: 1
        $x_1_6 = "mellemteksten.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_ME_2147896084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.ME!MTB"
        threat_id = "2147896084"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "FileOperator.exe" ascii //weight: 3
        $x_3_2 = "ODControl.dll" ascii //weight: 3
        $x_3_3 = "OpenSSL-License.txt" ascii //weight: 3
        $x_3_4 = "SetupAURACreator.exe" ascii //weight: 3
        $x_3_5 = "Argo AI" ascii //weight: 3
        $x_3_6 = "Delete on reboot" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SUI_2147905166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SUI!MTB"
        threat_id = "2147905166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "baggrundsprocessens traumatologies" wide //weight: 2
        $x_2_2 = "ligesaavel phyllostachys" wide //weight: 2
        $x_2_3 = "pulvereous helbredsgrundes discoid" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SUI_2147905166_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SUI!MTB"
        threat_id = "2147905166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "skrubtudse" ascii //weight: 1
        $x_1_2 = "glossolaryngeal hangee iscenestte" ascii //weight: 1
        $x_1_3 = "udvejer" ascii //weight: 1
        $x_1_4 = "saarskorpen xenomi antispiritualism" ascii //weight: 1
        $x_1_5 = "afsgningerne takketalernes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SUI_2147905166_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SUI!MTB"
        threat_id = "2147905166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ationalitetsmrket\\isonomic\\Subtersuperlative\\Vehftets\\skybanken.emp" ascii //weight: 1
        $x_1_2 = "bygningernes" ascii //weight: 1
        $x_1_3 = "skybanken.emp" ascii //weight: 1
        $x_1_4 = "screamed rumbaing sootish" ascii //weight: 1
        $x_1_5 = "brndemrkningerne" ascii //weight: 1
        $x_1_6 = "jetes ischury" ascii //weight: 1
        $x_1_7 = "seismometeret rustedes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_AA_2147912666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.AA!MTB"
        threat_id = "2147912666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 75 04 31 c0 [0-32] 66 8b 04 4e [0-32] 8b 75 14 [0-32] 03 75 04 8b 34 86 [0-32] 03 75 04 89 75 08 [0-32] c2 04 00}  //weight: 10, accuracy: Low
        $x_1_2 = {46 80 3e 00 0f 85 ?? ?? ff ff c2 04 00 [0-32] 31 c0 [0-32] c2 04 00}  //weight: 1, accuracy: Low
        $x_1_3 = {01 d8 0f b6 0e 01 c8}  //weight: 1, accuracy: High
        $x_10_4 = {89 d6 60 0f 31 b8 ?? ?? ?? ?? 04 01 01 01 01 05 35 2d b8 ?? ?? ?? ?? 04 01 01 01 01 05 35 2d b8 ?? ?? ?? ?? 04 01 01 01 01 05 35 2d b8 ?? ?? ?? ?? 0f a2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_GuLoader_NG_2147914184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.NG!MTB"
        threat_id = "2147914184"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "klassifikationen.Sur" ascii //weight: 1
        $x_1_2 = "mediative\\prioriteterne\\smuglings" ascii //weight: 1
        $x_1_3 = "beklages.lnk" ascii //weight: 1
        $x_1_4 = "Besaetter\\Propagandism.Ens" ascii //weight: 1
        $x_1_5 = "bassetternes.for" ascii //weight: 1
        $x_1_6 = "Crackerberry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_NG_2147914184_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.NG!MTB"
        threat_id = "2147914184"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "upstay.fac" ascii //weight: 1
        $x_1_2 = "septenarii\\pelsbereder\\sammenfatningen" ascii //weight: 1
        $x_1_3 = "suderne.fas" ascii //weight: 1
        $x_1_4 = "stratificerendes.hen" ascii //weight: 1
        $x_1_5 = "Partaker195.est" ascii //weight: 1
        $x_1_6 = "merinould.mon" ascii //weight: 1
        $x_1_7 = "fraadserierne.rip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_NG_2147914184_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.NG!MTB"
        threat_id = "2147914184"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "undsttelsernes underlbendes blecidere" wide //weight: 2
        $x_2_2 = "casanova subbookkeeper" wide //weight: 2
        $x_2_3 = "haustrum wasir" wide //weight: 2
        $x_1_4 = "dybdepsykologs dolktid urinvejssygdommens" wide //weight: 1
        $x_1_5 = "besejledes.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_HNA_2147917861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.HNA!MTB"
        threat_id = "2147917861"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {ae 98 75 9e 8a 6d 00 00 00 be b4 b1 b8 af ad e0}  //weight: 10, accuracy: High
        $x_5_2 = {ea 9d 12 f3 b0 14 f9 c4 16 ee c4 1b bd 95 4b 8c 77 69 88 73 67 86 73 68 82 6f 64 80 71 6b 00 00}  //weight: 5, accuracy: High
        $x_1_3 = {83 e9 30 2c 53 c6 45 d6 04 f6 d8 1b c0 f7 d0 23 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_NL_2147917959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.NL!MTB"
        threat_id = "2147917959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "skatkammer.opt" ascii //weight: 2
        $x_2_2 = "underskriftindsmlinger.man" ascii //weight: 2
        $x_1_3 = "Nonsuccour.whi" ascii //weight: 1
        $x_1_4 = "Elokvent.hal" ascii //weight: 1
        $x_1_5 = "Forgring.sam" ascii //weight: 1
        $x_1_6 = "blommehave" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RSD_2147919598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RSD!MTB"
        threat_id = "2147919598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "krebanens\\Antianaphylactogen18" ascii //weight: 1
        $x_1_2 = "-\\almacen\\forskansning\\attributvrditildelings" ascii //weight: 1
        $x_1_3 = "%fringer%\\metoderne\\symphonist" ascii //weight: 1
        $x_1_4 = "99\\galtrap\\fraskrevne.ini" ascii //weight: 1
        $x_1_5 = "noncertainty\\sandarter" ascii //weight: 1
        $x_1_6 = "Minigrants152.txt" ascii //weight: 1
        $x_1_7 = "subconsulship begramsedes.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RSH_2147925145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RSH!MTB"
        threat_id = "2147925145"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "amygdale\\Uinitialiseret\\restriktivitetens" ascii //weight: 1
        $x_1_2 = "#\\Selvhjtidelig\\calodemonial.ini" ascii //weight: 1
        $x_1_3 = "\\megaara.Cer" ascii //weight: 1
        $x_1_4 = "frekvensomraaderne gliadines" ascii //weight: 1
        $x_1_5 = "precontention unperforating" ascii //weight: 1
        $x_1_6 = "andedammene elektronrret" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RSI_2147925419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RSI!MTB"
        threat_id = "2147925419"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Shrilling221\\melanemia" ascii //weight: 1
        $x_1_2 = "99\\Dkvingernes88\\malaga" ascii //weight: 1
        $x_1_3 = "#\\afsindigstes\\physitheism\\altingsmedlemmet" ascii //weight: 1
        $x_1_4 = "indefensibly\\antiatomkampagnen" ascii //weight: 1
        $x_1_5 = "Levnedsmiddelet.hyd" ascii //weight: 1
        $x_1_6 = "vejningers.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RSJ_2147925465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RSJ!MTB"
        threat_id = "2147925465"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\replaster\\uninterpleaded" ascii //weight: 1
        $x_1_2 = "Recants\\kirsebrsten\\rhesuspositiv" ascii //weight: 1
        $x_1_3 = "99\\multiplicere\\mortify.Pun" ascii //weight: 1
        $x_1_4 = "$$\\Grecianize\\turritellidae.ini" ascii //weight: 1
        $x_1_5 = "%Undergrundsbane%\\Akkusativobjekterne.Tan" ascii //weight: 1
        $x_1_6 = "mechanicalizations.bla" ascii //weight: 1
        $x_1_7 = "regalers.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RSL_2147925570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RSL!MTB"
        threat_id = "2147925570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Lividities\\indlaegger\\noncapillaries" ascii //weight: 1
        $x_1_2 = "88\\Disrespective\\mouseweb.sup" ascii //weight: 1
        $x_1_3 = "7\\caryophyllene.bac" ascii //weight: 1
        $x_1_4 = "%Farcicality115%\\venus" ascii //weight: 1
        $x_1_5 = "\\bearnaisens\\lejen.mac" ascii //weight: 1
        $x_1_6 = "kolonialt billedtppet.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RSN_2147925654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RSN!MTB"
        threat_id = "2147925654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "5\\bedvelsens\\Reaccelerates.ske" ascii //weight: 1
        $x_1_2 = "loddebolt\\Newsdealers" ascii //weight: 1
        $x_1_3 = "%biosynthesize%\\multipartite\\sigvard" ascii //weight: 1
        $x_1_4 = "\\retskrivningsreglens\\domestikvrelses.ini" ascii //weight: 1
        $x_1_5 = "bjergbestigningerne" ascii //weight: 1
        $x_1_6 = "vulgarizer.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RSB_2147932408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RSB!MTB"
        threat_id = "2147932408"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\ashipboard\\kellen\\knos" ascii //weight: 1
        $x_1_2 = "\\Ordbogs\\adjudantsnorenes.Ext241" ascii //weight: 1
        $x_1_3 = "\\Mellemmndenes224.ini" ascii //weight: 1
        $x_1_4 = "%vejlednings%\\artillerymen\\woodhung.pra" ascii //weight: 1
        $x_1_5 = "\\gennemtrawles\\gastroskopierne.dll" ascii //weight: 1
        $x_1_6 = "\\hydranths\\Dynamistic.pre" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RSE_2147932819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RSE!MTB"
        threat_id = "2147932819"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\fejltastning\\femdobler\\quasiparticle" ascii //weight: 1
        $x_1_2 = "99\\inhabilitetssprgsmaalet.tic" ascii //weight: 1
        $x_1_3 = "rekompenseres.jpg" ascii //weight: 1
        $x_1_4 = "uforsvarligheds regulatory overknowing" ascii //weight: 1
        $x_1_5 = "undergrundskulturerne" ascii //weight: 1
        $x_1_6 = "unconformity nonimputatively.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RSF_2147932961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RSF!MTB"
        threat_id = "2147932961"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dommedagsprdikenens johnnis" ascii //weight: 1
        $x_1_2 = "vignetted" ascii //weight: 1
        $x_1_3 = "kodes" ascii //weight: 1
        $x_1_4 = "toggler triumvirates.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RSG_2147932999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RSG!MTB"
        threat_id = "2147932999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "charpiet\\Summertide245\\Anskueligt" ascii //weight: 1
        $x_1_2 = "motatory\\Gudmdrene\\krematorier" ascii //weight: 1
        $x_1_3 = "%Ineffektiviteterne40%\\bejape\\Lullet210" ascii //weight: 1
        $x_1_4 = "%Trabucos%\\protestations\\unfiendlike" ascii //weight: 1
        $x_1_5 = "\\funke\\Befolkningsttheders75.kal" ascii //weight: 1
        $x_1_6 = "\\Sugeskive140.smu" ascii //weight: 1
        $x_1_7 = "genfremstilles dmringer.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RSK_2147933300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RSK!MTB"
        threat_id = "2147933300"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "unstraightened\\unpredicable\\konstance" ascii //weight: 1
        $x_1_2 = "\\dynelfterne\\fremmedpolitis.Afk" ascii //weight: 1
        $x_1_3 = "%kajpladserne%\\cordies\\participerendes.Ann" ascii //weight: 1
        $x_1_4 = "5\\Snespurve.Mys" ascii //weight: 1
        $x_1_5 = "\\breathalyze\\adults.loc" ascii //weight: 1
        $x_1_6 = "#\\Disallowance232\\*.vej" ascii //weight: 1
        $x_1_7 = "busseronne.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RSO_2147933773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RSO!MTB"
        threat_id = "2147933773"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vakuumers\\sundhedsplejerskers\\Skyggerne" ascii //weight: 1
        $x_1_2 = "Ansttelsesplaners\\Metalloid205\\Septics" ascii //weight: 1
        $x_1_3 = "%unreckingness%\\Squelchy\\kngtet" ascii //weight: 1
        $x_1_4 = "indmuret garagelejens decrustation" ascii //weight: 1
        $x_1_5 = "konsolideringernes sammensattes" ascii //weight: 1
        $x_1_6 = "squilgees.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RSQ_2147933793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RSQ!MTB"
        threat_id = "2147933793"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\conclusiveness\\aflirende\\kavaic" ascii //weight: 1
        $x_1_2 = "\\didactive\\eneprokura.ini" ascii //weight: 1
        $x_1_3 = "kompaktheden\\Indfoerelsen126" ascii //weight: 1
        $x_1_4 = "unconnectedness famelic" ascii //weight: 1
        $x_1_5 = "sprink forsvarsvrkers klovbeskring" ascii //weight: 1
        $x_1_6 = "skims trogon skridtkilen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RSR_2147934158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RSR!MTB"
        threat_id = "2147934158"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\majolicas\\protonemata\\operationsvrelser" ascii //weight: 1
        $x_1_2 = "televaerket\\sladdertasker.sti" ascii //weight: 1
        $x_1_3 = "ilfre\\indskuds\\" ascii //weight: 1
        $x_1_4 = "tripod eksklusives" ascii //weight: 1
        $x_1_5 = "blokkryptografis indsendelserne ibenholtsfljtes" ascii //weight: 1
        $x_1_6 = "antibiotikaforbruget.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RSS_2147934159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RSS!MTB"
        threat_id = "2147934159"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Faginspektrerne\\affugt\\dunter" ascii //weight: 1
        $x_1_2 = "\\constancy.ans" ascii //weight: 1
        $x_1_3 = "Lbrikkernes46.ini" ascii //weight: 1
        $x_1_4 = "claxon rejicere" ascii //weight: 1
        $x_1_5 = "impugner tikantens mediaanalyse" ascii //weight: 1
        $x_1_6 = "kammerjunkerne.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RST_2147934167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RST!MTB"
        threat_id = "2147934167"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "flighting redescribes nasioinial" ascii //weight: 1
        $x_1_2 = "autodidakte leah bubas" ascii //weight: 1
        $x_1_3 = "lampatia" ascii //weight: 1
        $x_1_4 = "dovetailwise.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RSU_2147934241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RSU!MTB"
        threat_id = "2147934241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Skolings\\Logikkerne101\\chirologies" ascii //weight: 1
        $x_1_2 = "synaxar\\nonvirtuousness\\resaca" ascii //weight: 1
        $x_1_3 = "5\\tilbagedateringernes\\Forrevnes229.aff" ascii //weight: 1
        $x_1_4 = "\\undertide\\bessermachen.ini" ascii //weight: 1
        $x_1_5 = "kvrulerendes" ascii //weight: 1
        $x_1_6 = "Flagellants.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RSV_2147934253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RSV!MTB"
        threat_id = "2147934253"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "digtcyklens aarringene" ascii //weight: 1
        $x_1_2 = "filsti laggards.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RSW_2147934448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RSW!MTB"
        threat_id = "2147934448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\startparametrets\\Anablepses124\\Spisebler" ascii //weight: 1
        $x_1_2 = "99\\perturbingly\\metaplasis.for" ascii //weight: 1
        $x_1_3 = "\\typhemia.atm" ascii //weight: 1
        $x_1_4 = "syntaksanalyserne codevelop" ascii //weight: 1
        $x_1_5 = "haervaerk pendanter" ascii //weight: 1
        $x_1_6 = "tvangsfuldbyrder.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RSX_2147934458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RSX!MTB"
        threat_id = "2147934458"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#\\Kalkvrksarbejderen84\\chego\\reverensens" ascii //weight: 1
        $x_1_2 = "supernovas\\mesalliancers\\Seksaaringen" ascii //weight: 1
        $x_1_3 = "\\betrngtes\\hockshin.Toe" ascii //weight: 1
        $x_1_4 = "bimahs weensier spildevandsledningernes" ascii //weight: 1
        $x_1_5 = "influenzaepidemiens doktoren" ascii //weight: 1
        $x_1_6 = "nadvergst.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RSY_2147934560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RSY!MTB"
        threat_id = "2147934560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ethanim pig domsudskrift" ascii //weight: 1
        $x_1_2 = "bombyciform fljlerne sesquiduple" ascii //weight: 1
        $x_1_3 = "formaalsls frues melanie" ascii //weight: 1
        $x_1_4 = "fladbarmet" ascii //weight: 1
        $x_1_5 = "infeasibilities aquaduct.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RSZ_2147934598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RSZ!MTB"
        threat_id = "2147934598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "invention tyngdepunktsforskydningerne" ascii //weight: 1
        $x_1_2 = "beskatningsformers underspilningens" ascii //weight: 1
        $x_1_3 = "folketroen cladocerous" ascii //weight: 1
        $x_1_4 = "surmlk screams cisset" ascii //weight: 1
        $x_1_5 = "skinnebusserne" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SRG_2147934637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SRG!MTB"
        threat_id = "2147934637"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Unbeing55\\kroer\\tingid" ascii //weight: 1
        $x_1_2 = "Bosteder5.soc" ascii //weight: 1
        $x_1_3 = "Filstruktur.txt" ascii //weight: 1
        $x_1_4 = "copaline.unc" ascii //weight: 1
        $x_1_5 = "destemper.txt" ascii //weight: 1
        $x_1_6 = "ferske.kap" ascii //weight: 1
        $x_1_7 = "undergivelsens.ini" ascii //weight: 1
        $x_1_8 = "\\proctoclysis\\rosetan.fis" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBA_2147934680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RBA!MTB"
        threat_id = "2147934680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sandfanget\\ophavsretsindehavers\\marmorflisens" ascii //weight: 1
        $x_1_2 = "\\supervacaneous\\forestillingsverdner.col" ascii //weight: 1
        $x_1_3 = "5\\episodernes\\Multiscreen.fra" ascii //weight: 1
        $x_1_4 = "%unoratorial%\\universitetsforlag" ascii //weight: 1
        $x_1_5 = "sati sprogklft saronide" ascii //weight: 1
        $x_1_6 = "kookier atropinet" ascii //weight: 1
        $x_1_7 = "stinkbranden" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBB_2147934688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RBB!MTB"
        threat_id = "2147934688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Milieubeskyttelsessektorer\\Acetylene" ascii //weight: 1
        $x_1_2 = "ts\\ekstrafortjenestes.Rke" ascii //weight: 1
        $x_1_3 = "%sitre%\\sidsers.Adr" ascii //weight: 1
        $x_1_4 = "smitsommeste rdlerets" ascii //weight: 1
        $x_1_5 = "mononitride fiskekutter injects" ascii //weight: 1
        $x_1_6 = "vocoded differentieringer.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBC_2147934700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RBC!MTB"
        threat_id = "2147934700"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\bibliografers.tol" ascii //weight: 1
        $x_1_2 = "\\Flimp137" ascii //weight: 1
        $x_1_3 = "skbnebestemte corodiary" ascii //weight: 1
        $x_1_4 = "kikori" ascii //weight: 1
        $x_1_5 = "registernavnenes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBD_2147934845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RBD!MTB"
        threat_id = "2147934845"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "verdenslitteraturerne" ascii //weight: 1
        $x_1_2 = "mirza enunciation" ascii //weight: 1
        $x_1_3 = "byretsdommeres.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBE_2147934990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RBE!MTB"
        threat_id = "2147934990"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ails gnathic afskrkkelsesvaabnet" ascii //weight: 1
        $x_1_2 = "mesosigmoid udfyldningrs" ascii //weight: 1
        $x_1_3 = "yor sebum discreet" ascii //weight: 1
        $x_1_4 = "usikkerhedsmomentets dekodningers.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_GuLoader_RBF_2147935104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RBF!MTB"
        threat_id = "2147935104"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Atrierne\\Uninstall\\Cashewnddernes29\\unsummarisable" ascii //weight: 1
        $x_1_2 = "\\amphithalamus\\indkaldelsesdagene.dll" ascii //weight: 1
        $x_1_3 = "\\calendarial\\wabblingly.Uno" ascii //weight: 1
        $x_1_4 = "%transportmidlets%\\beskuelses.mar" ascii //weight: 1
        $x_1_5 = "parietojugal" ascii //weight: 1
        $x_1_6 = "chompers okkeres inconditioned" ascii //weight: 1
        $x_1_7 = "perishers troopials boraks" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBG_2147935278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RBG!MTB"
        threat_id = "2147935278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "inddatafelt" ascii //weight: 1
        $x_1_2 = "frivolized undergrundskonomiernes" ascii //weight: 1
        $x_1_3 = "storebroders" ascii //weight: 1
        $x_1_4 = "licans voldelighederne.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBH_2147935324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RBH!MTB"
        threat_id = "2147935324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\exulding\\genrebestemmelses" ascii //weight: 1
        $x_1_2 = "Bifloderne90.ini" ascii //weight: 1
        $x_1_3 = "marmeladen arbitrated" ascii //weight: 1
        $x_1_4 = "ichthyisms ic slvtj" ascii //weight: 1
        $x_1_5 = "civilkonomerne bidirectional" ascii //weight: 1
        $x_1_6 = "thelmas.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBI_2147935332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RBI!MTB"
        threat_id = "2147935332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Burlington Resources Inc." ascii //weight: 1
        $x_1_2 = "Bowater Incorporated" ascii //weight: 1
        $x_1_3 = "Siebel Systems Inc" ascii //weight: 1
        $x_1_4 = "Landstar System Inc." ascii //weight: 1
        $x_1_5 = "fiendliness horrorful.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBJ_2147935382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RBJ!MTB"
        threat_id = "2147935382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Siliciumets\\trykketeknikkerne\\livsforsikringens" ascii //weight: 1
        $x_1_2 = "%Pseudoanatomic%\\Krocket22" ascii //weight: 1
        $x_1_3 = "5\\Snorkel.Eve" ascii //weight: 1
        $x_1_4 = "mellemgangene moerket resituates" ascii //weight: 1
        $x_1_5 = "visitation baggages" ascii //weight: 1
        $x_1_6 = "semicollegiate.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBK_2147935664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RBK!MTB"
        threat_id = "2147935664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bombardements skattereformen" ascii //weight: 1
        $x_1_2 = "ummps vinkelhastighedernes" ascii //weight: 1
        $x_1_3 = "skrigenes" ascii //weight: 1
        $x_1_4 = "dolcan.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBL_2147935769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RBL!MTB"
        threat_id = "2147935769"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "subformativeness chartringens pjkkeriet" ascii //weight: 1
        $x_1_2 = "schrecklich" ascii //weight: 1
        $x_1_3 = "dreamingful figureheads zoologer" ascii //weight: 1
        $x_1_4 = "tvangsrutens inversions.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBM_2147935856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RBM!MTB"
        threat_id = "2147935856"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "callityped awaruite mesropian" ascii //weight: 1
        $x_1_2 = "undersaturation numberous" ascii //weight: 1
        $x_1_3 = "raavarepris" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBN_2147935960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RBN!MTB"
        threat_id = "2147935960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#\\briskly\\townhouses\\Informationsbehandling80" ascii //weight: 1
        $x_1_2 = "$$\\unfrigidness\\prsentation.une" ascii //weight: 1
        $x_1_3 = "88\\Bluejelly78\\infinituple.tet" ascii //weight: 1
        $x_1_4 = "dramaet triflier dirigenternes" ascii //weight: 1
        $x_1_5 = "bridgemaking rgningens" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBN_2147935960_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RBN!MTB"
        threat_id = "2147935960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sovseskeernes\\uncompliability\\kriteriernes" ascii //weight: 1
        $x_1_2 = "%Unprisonable%\\Onomastical\\Diskurser.unt" ascii //weight: 1
        $x_1_3 = "encyklopdiers indissolubly afspndingsmidlernes" ascii //weight: 1
        $x_1_4 = "nontentative floppenes amplituders" ascii //weight: 1
        $x_1_5 = "sementera" ascii //weight: 1
        $x_1_6 = "reproclaim" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBO_2147936611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RBO!MTB"
        threat_id = "2147936611"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "balkanland parameterfremstillingers forannvnt" ascii //weight: 1
        $x_1_2 = "spildevandsbekendtgrelsens nonliquidating" ascii //weight: 1
        $x_1_3 = "kvllernes spondias molendinary" ascii //weight: 1
        $x_1_4 = "backburn" ascii //weight: 1
        $x_1_5 = "angionoma.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBP_2147937067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RBP!MTB"
        threat_id = "2147937067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "respondenterne valgflskets defacer" ascii //weight: 1
        $x_1_2 = "nonalliteratively" ascii //weight: 1
        $x_1_3 = "dawt interarmy" ascii //weight: 1
        $x_1_4 = "loudliest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBQ_2147937166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RBQ!MTB"
        threat_id = "2147937166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "johnadreams bladmave embossed" ascii //weight: 1
        $x_1_2 = "precontemporary" ascii //weight: 1
        $x_1_3 = "depressivt" ascii //weight: 1
        $x_1_4 = "intermorainic rectifier" ascii //weight: 1
        $x_1_5 = "stiltifying registertekstens.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBR_2147937312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RBR!MTB"
        threat_id = "2147937312"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Polyphyletic\\Wages93" ascii //weight: 1
        $x_1_2 = "knsrolledebatterne jockeyism" ascii //weight: 1
        $x_1_3 = "pudsenmager" ascii //weight: 1
        $x_1_4 = "malmsey minimumskravet.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBS_2147937378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RBS!MTB"
        threat_id = "2147937378"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-\\groteskes\\Pletten113\\fldeskummen" ascii //weight: 1
        $x_1_2 = "%shufflingly%\\reporterede\\Nonnatives" ascii //weight: 1
        $x_1_3 = "\\mayorships\\Epidemiologiens.ini" ascii //weight: 1
        $x_1_4 = "bodiced palaeontography arbejdspapirerne" ascii //weight: 1
        $x_1_5 = "kulbrinterne aabnemuskels.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBT_2147937385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RBT!MTB"
        threat_id = "2147937385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%reunionism%\\billarderne\\transpositively" ascii //weight: 1
        $x_1_2 = "serviceprisers cedule furrowlike" ascii //weight: 1
        $x_1_3 = "moppernes faengslende scioptics" ascii //weight: 1
        $x_1_4 = "staalampes unpassableness" ascii //weight: 1
        $x_1_5 = "converging antenneforeningerne.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBV_2147937567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RBV!MTB"
        threat_id = "2147937567"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "elefanthuerne eneherredmmes" ascii //weight: 1
        $x_1_2 = "grammatikernes" ascii //weight: 1
        $x_1_3 = "calzone" ascii //weight: 1
        $x_1_4 = "furcula.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBW_2147937709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RBW!MTB"
        threat_id = "2147937709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\jezail\\spurveungernes" ascii //weight: 1
        $x_1_2 = "\\plankevrket\\petunia" ascii //weight: 1
        $x_1_3 = "dampskibsforbindelse brogues humorproof" ascii //weight: 1
        $x_1_4 = "posnanian" ascii //weight: 1
        $x_1_5 = "anvendelsesformaalenes closeout.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBX_2147937955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RBX!MTB"
        threat_id = "2147937955"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "indeslut fritidsbukser kvadersten" ascii //weight: 1
        $x_1_2 = "ferierejsende scruple" ascii //weight: 1
        $x_1_3 = "hvordan" ascii //weight: 1
        $x_1_4 = "premourn" ascii //weight: 1
        $x_1_5 = "proffesionelle.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBY_2147938418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RBY!MTB"
        threat_id = "2147938418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Witnessers153\\raabte\\amuletters" ascii //weight: 1
        $x_1_2 = "reasonings demoraliser radioamplifier" ascii //weight: 1
        $x_1_3 = "commingler dialyses" ascii //weight: 1
        $x_1_4 = "swordgrass" ascii //weight: 1
        $x_1_5 = "apprizal.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBZ_2147938546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RBZ!MTB"
        threat_id = "2147938546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\arizonians\\tollo" ascii //weight: 1
        $x_1_2 = "inds antiproductive pantometrical" ascii //weight: 1
        $x_1_3 = "intelligencer praktikable" ascii //weight: 1
        $x_1_4 = "trochaicality achromotrichia unomnipotently" ascii //weight: 1
        $x_1_5 = "barmhjertigt" ascii //weight: 1
        $x_1_6 = "anticiperet skrvebelgningens" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RAA_2147938672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RAA!MTB"
        threat_id = "2147938672"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\pladsholderes\\cithrens\\monometalism" ascii //weight: 1
        $x_1_2 = "%Testkrslernes%\\tehtten" ascii //weight: 1
        $x_1_3 = "swagbellies dequeued" ascii //weight: 1
        $x_1_4 = "dyvel apotekerdisciplen" ascii //weight: 1
        $x_1_5 = "menualternativernes.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RAB_2147939035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RAB!MTB"
        threat_id = "2147939035"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\antoni\\Kiaugh90\\spiralfjedrene" ascii //weight: 1
        $x_1_2 = "tidsprioriteringerne almennyttigt kanawha" ascii //weight: 1
        $x_1_3 = "styreprograms" ascii //weight: 1
        $x_1_4 = "basilikumen zach" ascii //weight: 1
        $x_1_5 = "sobe aarsbudgettet.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RAC_2147939163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RAC!MTB"
        threat_id = "2147939163"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Servietter\\forfends\\ecclesiae" ascii //weight: 1
        $x_1_2 = "Tatariskes\\gerningers\\" ascii //weight: 1
        $x_1_3 = "Kondicyklens.ini" ascii //weight: 1
        $x_1_4 = "%afviklingstids%\\fjerde\\driftsomkostnings" ascii //weight: 1
        $x_1_5 = "\\rasher\\tilfredsstillelsen.jpg" ascii //weight: 1
        $x_1_6 = "%tilst%\\skolingsgrupper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RAD_2147939278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RAD!MTB"
        threat_id = "2147939278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "suppressants\\Pythonical\\skattepolitiks" ascii //weight: 1
        $x_1_2 = "#\\strafudmaalingen\\reverent" ascii //weight: 1
        $x_1_3 = "%%\\vildttllinger.ini" ascii //weight: 1
        $x_1_4 = "transversal stvningsmands sykofanternes" ascii //weight: 1
        $x_1_5 = "douping prokuraerne vicentes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RAE_2147939320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RAE!MTB"
        threat_id = "2147939320"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "deafeningly demonifuge" ascii //weight: 1
        $x_1_2 = "lektiernes centralskoles" ascii //weight: 1
        $x_1_3 = "vederheftighederne.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RAF_2147939795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RAF!MTB"
        threat_id = "2147939795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%isometri%\\styrtdykkeren" ascii //weight: 1
        $x_1_2 = "5\\haandarbejdernes\\epoxyed.htm" ascii //weight: 1
        $x_1_3 = "langsommelige taverns bajeren" ascii //weight: 1
        $x_1_4 = "siers datateknikkers" ascii //weight: 1
        $x_1_5 = "infold daekker.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RAF_2147939795_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RAF!MTB"
        threat_id = "2147939795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\fejelistens\\ingrossing" ascii //weight: 1
        $x_1_2 = "%manyatta%\\displeasurement\\Underclutch193" ascii //weight: 1
        $x_1_3 = "\\sandwichmnd\\jennets.ini" ascii //weight: 1
        $x_1_4 = "lingerer formatlngdes" ascii //weight: 1
        $x_1_5 = "sermoning unionsdannelsers" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RAG_2147940325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RAG!MTB"
        threat_id = "2147940325"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "beskyttelsesvrdige karle" ascii //weight: 1
        $x_1_2 = "prorektorers descendent noncasuistically" ascii //weight: 1
        $x_1_3 = "sylnnen aftrkningens dizorganisation" ascii //weight: 1
        $x_1_4 = "broderparrene.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RAH_2147940692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RAH!MTB"
        threat_id = "2147940692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Kobberstikket169\\helicograph" ascii //weight: 1
        $x_1_2 = "%mulishness%\\Nonleaking.bin" ascii //weight: 1
        $x_1_3 = "galeidae oparbejdelsernes outbear" ascii //weight: 1
        $x_1_4 = "eftersidninger bistandsklientens unsuperficial" ascii //weight: 1
        $x_1_5 = "skillevgge" ascii //weight: 1
        $x_1_6 = "dedicerendes sintoism.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RAI_2147940822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RAI!MTB"
        threat_id = "2147940822"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "brachiata hyphenation electrotonise" ascii //weight: 1
        $x_1_2 = "mools" ascii //weight: 1
        $x_1_3 = "posologic rit.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

