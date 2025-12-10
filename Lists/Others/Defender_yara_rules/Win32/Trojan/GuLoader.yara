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

rule Trojan_Win32_GuLoader_KB_2147781662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.KB!MTB"
        threat_id = "2147781662"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "legatbestyrelserne autogyros" ascii //weight: 1
        $x_1_2 = "krasse befris desize" ascii //weight: 1
        $x_1_3 = "jowed" ascii //weight: 1
        $x_1_4 = "entohyal spaulder.exe" ascii //weight: 1
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

rule Trojan_Win32_GuLoader_SVM_2147933263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SVM!MTB"
        threat_id = "2147933263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "quadriciliate.txt" ascii //weight: 2
        $x_2_2 = "budgereegah.jpg" ascii //weight: 2
        $x_2_3 = "avisskriverier.jpg" ascii //weight: 2
        $x_2_4 = "Tekstmasses227.ini" ascii //weight: 2
        $x_2_5 = "Retroposed.jpg" ascii //weight: 2
        $x_2_6 = "Delbetalingers.txt" ascii //weight: 2
        $x_2_7 = "contractibleness\\breblgernes" ascii //weight: 2
        $x_1_8 = "skruetrkkeres.mus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SVM_2147933263_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SVM!MTB"
        threat_id = "2147933263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Skrigedukker\\fidusmalers" ascii //weight: 1
        $x_1_2 = "\\tortoise\\Laurbrs155.ini" ascii //weight: 1
        $x_1_3 = "Benzophenothiazine113.txt" ascii //weight: 1
        $x_1_4 = "Hyporhachis.kue" ascii //weight: 1
        $x_1_5 = "gavstrikkernes.tit" ascii //weight: 1
        $x_1_6 = "overburdeningly.rec" ascii //weight: 1
        $x_1_7 = "tetrasporangia.ven" ascii //weight: 1
        $x_1_8 = "\\fotografis.zip" ascii //weight: 1
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
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "udvlgelsesvinduets" ascii //weight: 1
        $x_1_2 = "hoejadelen" ascii //weight: 1
        $x_1_3 = "sejlbaads" ascii //weight: 1
        $x_1_4 = "highcourt.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBA_2147934680_1
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
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#\\imprgneringer\\Botilla\\hjlpefilens" ascii //weight: 1
        $x_1_2 = "quarterland" ascii //weight: 1
        $x_1_3 = "gastrophilus timeforbrugenes" ascii //weight: 1
        $x_1_4 = "steprelationship" ascii //weight: 1
        $x_1_5 = "grundlovstalens redhandedness.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBB_2147934688_1
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

rule Trojan_Win32_GuLoader_RBC_2147934700_1
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
        $x_1_1 = "levnets\\semireflexively" ascii //weight: 1
        $x_1_2 = "\\Desertioner\\uskikken.gif" ascii //weight: 1
        $x_1_3 = "\\aandsevner\\natricinae.ini" ascii //weight: 1
        $x_1_4 = "opkrvedes grafikprogrammer antitragal" ascii //weight: 1
        $x_1_5 = "macrosymbiont.exe" ascii //weight: 1
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

rule Trojan_Win32_GuLoader_RBD_2147934845_1
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
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kirkegange\\baltheus\\digression" ascii //weight: 1
        $x_1_2 = "Precosmically\\multihead" ascii //weight: 1
        $x_1_3 = "%seacross%\\solcreme" ascii //weight: 1
        $x_1_4 = "\\nooky\\Concolour.ini" ascii //weight: 1
        $x_1_5 = "\\spermatia" ascii //weight: 1
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

rule Trojan_Win32_GuLoader_RBE_2147934990_1
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
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Sybaritism\\Underprikkede" ascii //weight: 1
        $x_1_2 = "Skemalisterne.ini" ascii //weight: 1
        $x_1_3 = "\\kontortelefon\\octaval.jpg" ascii //weight: 1
        $x_1_4 = "afloesningsopgaven quantitiveness" ascii //weight: 1
        $x_1_5 = "boller" ascii //weight: 1
        $x_1_6 = "nedsablingen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
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
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Forceps\\restigmatises\\Torrence" ascii //weight: 1
        $x_1_2 = "\\Delegerets144\\dampningerne.kil" ascii //weight: 1
        $x_1_3 = "\\enterorrhea\\outtake.upf" ascii //weight: 1
        $x_1_4 = "%typebetegnelsers%\\chlorinator\\fogedretterne" ascii //weight: 1
        $x_1_5 = "kunstgdningers orkestergraven.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBF_2147935104_1
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

rule Trojan_Win32_GuLoader_RBG_2147935278_1
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
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Knight-Ridder Inc." ascii //weight: 1
        $x_1_2 = "Viad Corp" ascii //weight: 1
        $x_1_3 = "Medtronic Inc." ascii //weight: 1
        $x_1_4 = "Comfort Systems USA Inc." ascii //weight: 1
        $x_1_5 = "unreworded demimondn.exe" ascii //weight: 1
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
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "platilla triethylstibine spiseblers" ascii //weight: 1
        $x_1_2 = "satanism fairm" ascii //weight: 1
        $x_1_3 = "yarmelke gaunt.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBH_2147935324_1
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

rule Trojan_Win32_GuLoader_RBI_2147935332_1
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
        $x_1_1 = "\\repetrpr\\tabloidavis\\portsmouth" ascii //weight: 1
        $x_1_2 = "-\\betagelsers\\stifinderens.jpg" ascii //weight: 1
        $x_1_3 = "%blgede%\\hummeres\\unsad" ascii //weight: 1
        $x_1_4 = "7\\fylke\\scaphocerite.txt" ascii //weight: 1
        $x_1_5 = "fum espavel.exe" ascii //weight: 1
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
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Activate\\Cannibalization\\Distractible" ascii //weight: 1
        $x_1_2 = "konebytningens\\purismen\\pygmaean" ascii //weight: 1
        $x_1_3 = "%Azoturia%\\lumina" ascii //weight: 1
        $x_1_4 = "esurience interpretive" ascii //weight: 1
        $x_1_5 = "animhdr vicevrtens.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBJ_2147935382_1
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

rule Trojan_Win32_GuLoader_RBK_2147935664_1
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
        $x_1_1 = "Zions Bancorporation" ascii //weight: 1
        $x_1_2 = "Mirant Corporation" ascii //weight: 1
        $x_1_3 = "Regions Financial Corp." ascii //weight: 1
        $x_1_4 = "amalgameret.exe" ascii //weight: 1
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
        $x_1_1 = "WestPoint Stevens Inc" ascii //weight: 1
        $x_1_2 = "Valve Corporation" ascii //weight: 1
        $x_1_3 = "Medtronic Inc." ascii //weight: 1
        $x_1_4 = "guiltiest.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBL_2147935769_1
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

rule Trojan_Win32_GuLoader_RBM_2147935856_1
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
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\planular\\undervisningsomraadets" ascii //weight: 1
        $x_1_2 = "\\Fermenteret156\\occlusocervical" ascii //weight: 1
        $x_1_3 = "honoreredes.aut" ascii //weight: 1
        $x_1_4 = "\\Cathy\\*.bin" ascii //weight: 1
        $x_1_5 = "%muggery%\\Oxygens\\Fletfilen" ascii //weight: 1
        $x_1_6 = "\\enevrelser.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
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
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Allied Waste Industries, Inc." ascii //weight: 1
        $x_1_2 = "Metaldyne Corporation" ascii //weight: 1
        $x_1_3 = "Southwest Airlines Co" ascii //weight: 1
        $x_1_4 = "formblingen statuses.exe" ascii //weight: 1
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

rule Trojan_Win32_GuLoader_RBN_2147935960_2
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
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Coca-Cola Enterprises Inc." ascii //weight: 1
        $x_1_2 = "Outback Steakhouse Inc." ascii //weight: 1
        $x_1_3 = "Maxim Integrated Products Inc." ascii //weight: 1
        $x_1_4 = "diminishment.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBO_2147936611_1
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

rule Trojan_Win32_GuLoader_RBP_2147937067_1
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
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Parker Hannifin Corp." ascii //weight: 1
        $x_1_2 = "BMC Software Inc." ascii //weight: 1
        $x_1_3 = "Federal Mogul Corp." ascii //weight: 1
        $x_1_4 = "La-Z-Boy Inc." ascii //weight: 1
        $x_1_5 = "Smurfit-Stone Container Corp" ascii //weight: 1
        $x_1_6 = "markren gedekiddene.exe" ascii //weight: 1
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

rule Trojan_Win32_GuLoader_RBQ_2147937166_1
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
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Raspberry33\\Programudviklings" ascii //weight: 1
        $x_1_2 = "%bibeholdtes%\\beluredes" ascii //weight: 1
        $x_1_3 = "konometriske\\Stilsikre221\\tudkoppernes" ascii //weight: 1
        $x_1_4 = "\\aadselgravernes\\forlberens.jpg" ascii //weight: 1
        $x_1_5 = "Unvenerated.obo" ascii //weight: 1
        $x_1_6 = "gymnotoka.rea" ascii //weight: 1
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

rule Trojan_Win32_GuLoader_RBR_2147937312_1
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
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\forsmmelses\\galehus" ascii //weight: 1
        $x_1_2 = "\\westling\\skindhuerne.ini" ascii //weight: 1
        $x_1_3 = "\\trykkogeres.gif" ascii //weight: 1
        $x_1_4 = "\\Endestationers\\Selvbefrugtningernes.ini" ascii //weight: 1
        $x_1_5 = "\\Kraftudfoldelser\\Corrigibleness.lnk" ascii //weight: 1
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
        $x_1_1 = "Creephole\\Fodpleje\\cheminova" ascii //weight: 1
        $x_1_2 = "blindet\\Admiralers175" ascii //weight: 1
        $x_1_3 = "\\Magteslsest\\outgate.txt" ascii //weight: 1
        $x_1_4 = "%%\\nonforfeiture\\unslacking.ini" ascii //weight: 1
        $x_1_5 = "%elevskolerne%\\unlocalizables\\yvette" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBS_2147937378_1
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
        $x_1_1 = "gadekasernens\\nonnegligent\\supergallantness" ascii //weight: 1
        $x_1_2 = "%stickiest%\\christener\\udsteningen" ascii //weight: 1
        $x_1_3 = "\\sparable.bin" ascii //weight: 1
        $x_1_4 = "hyperbatbata twelvemo" ascii //weight: 1
        $x_1_5 = "hypotheses carbodynamite.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBT_2147937385_1
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

rule Trojan_Win32_GuLoader_RAJ_2147941037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RAJ!MTB"
        threat_id = "2147941037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\countercriticisms\\erector\\heltedigtene" ascii //weight: 1
        $x_1_2 = "kommunikationslinier.spr" ascii //weight: 1
        $x_1_3 = "kontrastering" ascii //weight: 1
        $x_1_4 = "paaskriftens vandtilfrslen" ascii //weight: 1
        $x_1_5 = "gruffish.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RAK_2147941227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RAK!MTB"
        threat_id = "2147941227"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rhinskes\\Terrorregimenternes" ascii //weight: 1
        $x_1_2 = "boretaarnets\\myosers" ascii //weight: 1
        $x_1_3 = "%mareridt%\\atestine.bin" ascii //weight: 1
        $x_1_4 = "hvarre slagtetiderne clusiaceous" ascii //weight: 1
        $x_1_5 = "unhospital hydrologisk.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RAL_2147941358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RAL!MTB"
        threat_id = "2147941358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\sovjetten\\privateness" ascii //weight: 1
        $x_1_2 = "%afbildninger%\\hovedtj\\salably.jpg" ascii //weight: 1
        $x_1_3 = "indsejlendes coloptosis" ascii //weight: 1
        $x_1_4 = "sponson" ascii //weight: 1
        $x_1_5 = "rhymemaking piltastens.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RAM_2147941450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RAM!MTB"
        threat_id = "2147941450"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "philogenitiveness kelds" ascii //weight: 1
        $x_1_2 = "appendices" ascii //weight: 1
        $x_1_3 = "floristic opver.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RAN_2147942220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RAN!MTB"
        threat_id = "2147942220"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\unniggard\\aggraveringens\\abettor" ascii //weight: 1
        $x_1_2 = "verpa bedmmelseskomiteen emigrerendes" ascii //weight: 1
        $x_1_3 = "saccage moralprdikener gadedrsnglers" ascii //weight: 1
        $x_1_4 = "magikernes.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_CCJZ_2147942670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.CCJZ!MTB"
        threat_id = "2147942670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Landeplager52.Tek" ascii //weight: 2
        $x_1_2 = "Trones.jpg" ascii //weight: 1
        $x_1_3 = "extenso.ini" ascii //weight: 1
        $x_1_4 = "priacanthidae.jpg" ascii //weight: 1
        $x_1_5 = "\\Vandlidende.Rug" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RAP_2147942847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RAP!MTB"
        threat_id = "2147942847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "clock skrmskemaer danic" ascii //weight: 1
        $x_1_2 = "sluttered" ascii //weight: 1
        $x_1_3 = "eugenius beskringernes" ascii //weight: 1
        $x_1_4 = "amfibietankenes.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_GuLoader_RAQ_2147942910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RAQ!MTB"
        threat_id = "2147942910"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%antimonopoly%\\muscavado\\Bustrafik" ascii //weight: 1
        $x_1_2 = "rutate kurv" ascii //weight: 1
        $x_1_3 = "halenesses trykstavelses undershine" ascii //weight: 1
        $x_1_4 = "sirup vulgres pretentiousnesses" ascii //weight: 1
        $x_1_5 = "misadjust konfigurationsprogram.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RAR_2147942930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RAR!MTB"
        threat_id = "2147942930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "staphylococcic garblings overbygningerne" ascii //weight: 1
        $x_1_2 = "fortrngninger" ascii //weight: 1
        $x_1_3 = "refragability gomasta" ascii //weight: 1
        $x_1_4 = "presubmitting klaustrofobi.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RAS_2147943225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RAS!MTB"
        threat_id = "2147943225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "prcedensens\\Barselsorlovernes\\retshjlpens" ascii //weight: 1
        $x_1_2 = "%Pointers%\\Prevalidly246\\Sammenklumpet" ascii //weight: 1
        $x_1_3 = "masturbation lserinderne" ascii //weight: 1
        $x_1_4 = "thakurate.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RAT_2147943599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RAT!MTB"
        threat_id = "2147943599"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "underopdelendes countertreason intensivering" ascii //weight: 1
        $x_1_2 = "svanesang sectarial" ascii //weight: 1
        $x_1_3 = "disaugment thrummed.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RAU_2147944014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RAU!MTB"
        threat_id = "2147944014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "crooklegged dean purrer" ascii //weight: 1
        $x_1_2 = "cosphered microtelephonic" ascii //weight: 1
        $x_1_3 = "coembedded skaertorsdag arbejdsmiljkonsulent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RAV_2147944489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RAV!MTB"
        threat_id = "2147944489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\contaminations\\drillesygeste" ascii //weight: 1
        $x_1_2 = "%rennases%\\indocibleness\\finansministrenes" ascii //weight: 1
        $x_1_3 = "%sidy%\\mygges\\Vidneafhringers" ascii //weight: 1
        $x_1_4 = "asellate\\Mummery119.exe" ascii //weight: 1
        $x_1_5 = "\\bolsjers\\Indlsendes.ini" ascii //weight: 1
        $x_1_6 = "\\narrene\\Karteuser125.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RAW_2147944605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RAW!MTB"
        threat_id = "2147944605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\udryddet\\Bengnaverne53\\udturenes" ascii //weight: 1
        $x_1_2 = "skovkanter\\bryan\\variocuopler" ascii //weight: 1
        $x_1_3 = "%Beadings%\\Abdomen\\Smirching" ascii //weight: 1
        $x_1_4 = "\\interrupter\\fotogrammetri.jpg" ascii //weight: 1
        $x_1_5 = "\\gorvarehandelen\\kendemrkers.htm" ascii //weight: 1
        $x_1_6 = "lighedspunkterne.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RAX_2147944869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RAX!MTB"
        threat_id = "2147944869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\kringlernes\\lumberjacks" ascii //weight: 1
        $x_1_2 = "ismejeri\\cordylanthus\\suppose" ascii //weight: 1
        $x_1_3 = "%tabers%\\afmonterer\\dillerdaller" ascii //weight: 1
        $x_1_4 = "\\Sprogbrugerne\\enerne.txt" ascii //weight: 1
        $x_1_5 = "buggymen coverchief besotting" ascii //weight: 1
        $x_1_6 = "korroder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SAF_2147945145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SAF!MTB"
        threat_id = "2147945145"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "kommpressorernes.uni" ascii //weight: 2
        $x_1_2 = "viderebringelsers.yan" ascii //weight: 1
        $x_1_3 = "unwarrantableness.ant" ascii //weight: 1
        $x_1_4 = "pararosaniline.haw" ascii //weight: 1
        $x_1_5 = "precisionism.for" ascii //weight: 1
        $x_1_6 = "vkkelsesprdikanter.ech" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RAY_2147945331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RAY!MTB"
        threat_id = "2147945331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "demokratiernes\\horograph\\stuporific" ascii //weight: 1
        $x_1_2 = "%thurst%\\indsmrer\\waldgravine" ascii //weight: 1
        $x_1_3 = "hygrometers sygesikringerne japanolatry" ascii //weight: 1
        $x_1_4 = "kampkunsts gambusia sondringerne" ascii //weight: 1
        $x_1_5 = "alchemister.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RAZ_2147945774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RAZ!MTB"
        threat_id = "2147945774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "polcpr vindicatively afsigende" ascii //weight: 1
        $x_1_2 = "uncogently ingulf" ascii //weight: 1
        $x_1_3 = "lateward loftsbelysningens geneviugves" ascii //weight: 1
        $x_1_4 = "bassett uncases reneglect" ascii //weight: 1
        $x_1_5 = "liggeplads valentino.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_NS_2147947244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.NS!MTB"
        threat_id = "2147947244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tilstandsform.wal" ascii //weight: 1
        $x_1_2 = "sekularismens.tre" ascii //weight: 1
        $x_1_3 = "immigrationen.jol" ascii //weight: 1
        $x_1_4 = "cindersbanernes.fic" ascii //weight: 1
        $x_1_5 = "outtricking\\Detentions\\liniefring" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_NS_2147947244_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.NS!MTB"
        threat_id = "2147947244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jerboa stabstamburs" ascii //weight: 1
        $x_1_2 = "subfebrile" ascii //weight: 1
        $x_1_3 = "genkendendes vellignendes" ascii //weight: 1
        $x_1_4 = "ekskluderet emendations.exe" ascii //weight: 1
        $x_1_5 = "fibrochondrosteal arbejdsmnd february" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_NS_2147947244_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.NS!MTB"
        threat_id = "2147947244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sagndannelses.jay" ascii //weight: 1
        $x_1_2 = "Centripetalkraftens151.mul" ascii //weight: 1
        $x_1_3 = "Pulverizes.Kom57" ascii //weight: 1
        $x_1_4 = "Chunari.Car" ascii //weight: 1
        $x_1_5 = "chiropraxis.kil" ascii //weight: 1
        $x_1_6 = "Itsy.kat" ascii //weight: 1
        $x_1_7 = "\\Lasten162\\Pulverizes.Kom57" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_NS_2147947244_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.NS!MTB"
        threat_id = "2147947244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Carnify.jpg" ascii //weight: 1
        $x_1_2 = "Dumpingpriss227.ret" ascii //weight: 1
        $x_1_3 = "chadors.fis" ascii //weight: 1
        $x_1_4 = "ordknappeste.dom" ascii //weight: 1
        $x_1_5 = "recipiomotor.ini" ascii //weight: 1
        $x_1_6 = "lyseslukker" ascii //weight: 1
        $x_1_7 = "Tamponadernes61" ascii //weight: 1
        $x_1_8 = "\\Dims49\\kreplan.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_NS_2147947244_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.NS!MTB"
        threat_id = "2147947244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ryddeligeres.gid" ascii //weight: 1
        $x_1_2 = "uens.rap" ascii //weight: 1
        $x_1_3 = "pistoleers.jpg" ascii //weight: 1
        $x_1_4 = "microcephal.epu" ascii //weight: 1
        $x_1_5 = "disadvise.txt" ascii //weight: 1
        $x_1_6 = "Baggrundsbillede.ini" ascii //weight: 1
        $x_1_7 = "Arvemassernes.jpg" ascii //weight: 1
        $x_1_8 = "manifestklr.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_NS_2147947244_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.NS!MTB"
        threat_id = "2147947244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ondskabsfulderes.ini" ascii //weight: 1
        $x_1_2 = "overbooked.jpg" ascii //weight: 1
        $x_1_3 = "laget.txt" ascii //weight: 1
        $x_1_4 = "intratomic.jpg" ascii //weight: 1
        $x_1_5 = "chambellan.ini" ascii //weight: 1
        $x_1_6 = "antimilitaristically.jpg" ascii //weight: 1
        $x_1_7 = "Preannouncement247.tha" ascii //weight: 1
        $x_1_8 = "Henrikkes.trn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_NS_2147947244_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.NS!MTB"
        threat_id = "2147947244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pleaser.kam" ascii //weight: 1
        $x_1_2 = "uncancelable\\irreligious\\gigtfebers" ascii //weight: 1
        $x_1_3 = "\\fribadestrandes\\*.gif" ascii //weight: 1
        $x_1_4 = "\\decarch.ini" ascii //weight: 1
        $x_1_5 = "terraciform\\Goatland\\knalleristens" ascii //weight: 1
        $x_1_6 = "astrakanskindets" ascii //weight: 1
        $x_1_7 = "\\hjaelpetekster.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_NS_2147947244_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.NS!MTB"
        threat_id = "2147947244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pulverisering.txt" ascii //weight: 1
        $x_1_2 = "quipo.tig" ascii //weight: 1
        $x_1_3 = "\\Medarbejders196.jpg" ascii //weight: 1
        $x_1_4 = "\\kloaknets.jpg" ascii //weight: 1
        $x_1_5 = "embedseksamens taygeta isazoxy" ascii //weight: 1
        $x_1_6 = "erotic annizettes.exe" ascii //weight: 1
        $x_1_7 = "horisontallinie" ascii //weight: 1
        $x_1_8 = "velstandssamfundet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_NS_2147947244_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.NS!MTB"
        threat_id = "2147947244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "extraterrestrially.hea" ascii //weight: 1
        $x_1_2 = "skinnecyklerne.wit" ascii //weight: 1
        $x_1_3 = "holes\\dosmersedlers\\Prefocusses" ascii //weight: 1
        $x_1_4 = "Dunlop.rek" ascii //weight: 1
        $x_1_5 = "Hippen11\\Forfgtelse\\" ascii //weight: 1
        $x_1_6 = "Bittesmaa208\\begrett\\misregulating" ascii //weight: 1
        $x_1_7 = "%%\\enaluron\\Schedule.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_NS_2147947244_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.NS!MTB"
        threat_id = "2147947244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "belurende" ascii //weight: 1
        $x_1_2 = "dissociation bionergy automatreaktion" ascii //weight: 1
        $x_1_3 = "picein" ascii //weight: 1
        $x_1_4 = "beskrivelsesvaerktoej.exe" ascii //weight: 1
        $x_1_5 = "alkoholikeren lokaliserendes" ascii //weight: 1
        $x_1_6 = "valutacentralen catfacing" ascii //weight: 1
        $x_1_7 = "sunfishery.hyd" ascii //weight: 1
        $x_1_8 = "vardapet.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_NS_2147947244_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.NS!MTB"
        threat_id = "2147947244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "trakkasseriet.ins" ascii //weight: 1
        $x_1_2 = "malachite.rek" ascii //weight: 1
        $x_1_3 = "datagram.sge" ascii //weight: 1
        $x_1_4 = "bonbonens" ascii //weight: 1
        $x_1_5 = "tropsfreres\\hjemfre\\tidsindstillende" ascii //weight: 1
        $x_1_6 = "branddaskers" ascii //weight: 1
        $x_1_7 = "\\Stoppekurve\\germanisere.lnk" ascii //weight: 1
        $x_1_8 = "Materialesamling109\\menighedens" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_NS_2147947244_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.NS!MTB"
        threat_id = "2147947244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "udvindinger.kon" ascii //weight: 1
        $x_1_2 = "envapours waylaidlessness histopathology" ascii //weight: 1
        $x_1_3 = "prosectorium.els" ascii //weight: 1
        $x_1_4 = "dikteringens.tra" ascii //weight: 1
        $x_1_5 = "arveretsligt.tri" ascii //weight: 1
        $x_1_6 = "debatfilmenes.exe" ascii //weight: 1
        $x_1_7 = "brnevenners" ascii //weight: 1
        $x_1_8 = "trinflger harpoons checkmates" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_NS_2147947244_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.NS!MTB"
        threat_id = "2147947244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "depending dyds moorage" ascii //weight: 1
        $x_1_2 = "dt talehandlinger" ascii //weight: 1
        $x_1_3 = "ristedes authoritarianism" ascii //weight: 1
        $x_1_4 = "oleaginous.exe" ascii //weight: 1
        $x_1_5 = "smaakravl" ascii //weight: 1
        $x_1_6 = "injektionerne" ascii //weight: 1
        $x_1_7 = "\\Sygeplejeassistent\\triseptate.jpg" ascii //weight: 1
        $x_1_8 = "bitestiklernes\\formninger\\litterateur" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_NS_2147947244_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.NS!MTB"
        threat_id = "2147947244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "slutningseffektens.txt" ascii //weight: 1
        $x_1_2 = "opgavehaandteringernes.txt" ascii //weight: 1
        $x_1_3 = "metaleptically.txt" ascii //weight: 1
        $x_1_4 = "familiesammenholds.cof" ascii //weight: 1
        $x_1_5 = "Umlaut196.jpg" ascii //weight: 1
        $x_1_6 = "calycozoic.ini" ascii //weight: 1
        $x_1_7 = "dermatolog teutophil presuming" ascii //weight: 1
        $x_1_8 = "diplochlamydeous underprisers bollandist" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_NS_2147947244_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.NS!MTB"
        threat_id = "2147947244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uforstandighederne.txt" ascii //weight: 1
        $x_1_2 = "supplemental.dag" ascii //weight: 1
        $x_1_3 = "mangelvarer.slu" ascii //weight: 1
        $x_1_4 = "Raspier.ini" ascii //weight: 1
        $x_1_5 = "strejftogs.blo" ascii //weight: 1
        $x_1_6 = "\\Nonfavored\\Kolonibestyreres" ascii //weight: 1
        $x_1_7 = "\\eurokommunismes\\vejfringerne" ascii //weight: 1
        $x_1_8 = "eftertndings\\civilsamfund\\billardkernes" ascii //weight: 1
        $x_1_9 = "Squelching154" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SUB_2147947316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SUB!MTB"
        threat_id = "2147947316"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\sceptry\\decibels\\prisklasser" ascii //weight: 1
        $x_1_2 = "\\reserveofficerers.jpg" ascii //weight: 1
        $x_1_3 = "\\kunstfrdigt.lnk" ascii //weight: 1
        $x_1_4 = "\\Cotylophorous\\Calvinisten.zip" ascii //weight: 1
        $x_1_5 = "\\affutager\\bougainvillaeas.ini" ascii //weight: 1
        $x_1_6 = "Prohumanistic1.sil" ascii //weight: 1
        $x_1_7 = "caravanist.mem" ascii //weight: 1
        $x_1_8 = "redaktren.fri" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SUD_2147947674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SUD!MTB"
        threat_id = "2147947674"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Saddeltags183" ascii //weight: 1
        $x_1_2 = "\\Soveposer\\brysthule.txt" ascii //weight: 1
        $x_1_3 = "\\Grusgrave191\\afgiftsordningernes.zip" ascii //weight: 1
        $x_1_4 = "Pyramidella.enj" ascii //weight: 1
        $x_1_5 = "Sentinelling.occ" ascii //weight: 1
        $x_1_6 = "betingede.pea" ascii //weight: 1
        $x_1_7 = "\\Turbojetternes129\\saneringsplaner.zip" ascii //weight: 1
        $x_1_8 = "\\bemused\\halicot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SUE_2147947753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SUE!MTB"
        threat_id = "2147947753"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\zarinas\\aareforfedtningens" ascii //weight: 1
        $x_1_2 = "\\Chapelry76.bmp" ascii //weight: 1
        $x_1_3 = "Deklamatorens.tro" ascii //weight: 1
        $x_1_4 = "Suttekludene.rel" ascii //weight: 1
        $x_1_5 = "dumrians.taf" ascii //weight: 1
        $x_1_6 = "prepend.kon" ascii //weight: 1
        $x_1_7 = "\\equiomnipotent\\vangers.txt" ascii //weight: 1
        $x_1_8 = "ridiculise\\tossehovedernes\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SUF_2147948324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SUF!MTB"
        threat_id = "2147948324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Balloteret.gif" ascii //weight: 1
        $x_1_2 = "\\acquent.ini" ascii //weight: 1
        $x_1_3 = "\\strandbredders.htm" ascii //weight: 1
        $x_1_4 = "\\Visioner\\postically.zip" ascii //weight: 1
        $x_1_5 = "\\pretrernes\\museums.jpg" ascii //weight: 1
        $x_1_6 = "ethylenically\\temblors.txt" ascii //weight: 1
        $x_1_7 = "\\Mea175.exe" ascii //weight: 1
        $x_1_8 = "\\dialogbokse\\nedslagtede.txt" ascii //weight: 1
        $x_1_9 = "\\uarbejdsdygtiges\\godsterminalernes.ini" ascii //weight: 1
        $x_1_10 = "Phenomenalize46.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SUG_2147948415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SUG!MTB"
        threat_id = "2147948415"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\parodi\\nonexceptionally.lnk" ascii //weight: 1
        $x_1_2 = "\\Venskabsbyernes234\\breaths.jpg" ascii //weight: 1
        $x_1_3 = "Godet65.gyt" ascii //weight: 1
        $x_1_4 = "gengldelsers.unf" ascii //weight: 1
        $x_1_5 = "overforsikre.med" ascii //weight: 1
        $x_1_6 = "summeriest.app" ascii //weight: 1
        $x_1_7 = "\\surcharges.ini" ascii //weight: 1
        $x_1_8 = "\\Snailery\\Administrant.ini" ascii //weight: 1
        $x_1_9 = "\\knledene.ini" ascii //weight: 1
        $x_1_10 = "\\abolitionised\\antiendowment.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_KMM_2147948579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.KMM!MTB"
        threat_id = "2147948579"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rachiomyelitis" ascii //weight: 1
        $x_1_2 = "dagsrutinernes" ascii //weight: 1
        $x_1_3 = "congenerical" ascii //weight: 1
        $x_1_4 = "\\Resnick.jpg" ascii //weight: 1
        $x_1_5 = "unparadoxically" ascii //weight: 1
        $x_1_6 = "Habsburgeren" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_GuLoader_SUJ_2147948731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SUJ!MTB"
        threat_id = "2147948731"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\lumberman.ini" ascii //weight: 1
        $x_1_2 = "patchworky\\Unbeveled" ascii //weight: 1
        $x_1_3 = "chingma\\Uninstall\\prerevised\\Kadaver67" ascii //weight: 1
        $x_1_4 = "\\art\\Pharynges.lnk" ascii //weight: 1
        $x_1_5 = "\\plotting\\glosserede.dll" ascii //weight: 1
        $x_1_6 = "givingly\\Husstv\\centrifugalsprederen" ascii //weight: 1
        $x_1_7 = "Beehive\\flleshuses\\Photopic" ascii //weight: 1
        $x_1_8 = "\\inappetence\\biplanerne\\Kamuflerendes.gif" ascii //weight: 1
        $x_1_9 = "\\Nedslaaedes174\\statsgarantiens.ini" ascii //weight: 1
        $x_1_10 = "\\usselheden\\tagpappens.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SUL_2147949548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SUL!MTB"
        threat_id = "2147949548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Reinjures\\medsendtes" ascii //weight: 1
        $x_1_2 = "\\tolvaarsfdselsdagen\\festugen" ascii //weight: 1
        $x_1_3 = "\\stemmejerns\\katodestraalernes.htm" ascii //weight: 1
        $x_1_4 = "\\Galactocele.ini" ascii //weight: 1
        $x_1_5 = "Remrkedes.sis" ascii //weight: 1
        $x_1_6 = "Brudfladen.Dra" ascii //weight: 1
        $x_1_7 = "Maleriudstillingerne98.jpg" ascii //weight: 1
        $x_1_8 = "\\Ottavas\\Kronerne" ascii //weight: 1
        $x_1_9 = "startbogstaver.bin" ascii //weight: 1
        $x_1_10 = "\\Brugsklart\\dataskrme.lnk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SUM_2147951733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SUM!MTB"
        threat_id = "2147951733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\almenhedens" ascii //weight: 1
        $x_1_2 = "\\Flokatis58.ini" ascii //weight: 1
        $x_1_3 = "\\Divertila" ascii //weight: 1
        $x_1_4 = "\\bearer.ini" ascii //weight: 1
        $x_1_5 = "bonkammeraters.fli" ascii //weight: 1
        $x_1_6 = "overordentliges.gul" ascii //weight: 1
        $x_1_7 = "overprsidiets.tin" ascii //weight: 1
        $x_1_8 = "sirki.kue" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SUN_2147951949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SUN!MTB"
        threat_id = "2147951949"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\bagflikninger\\mozarab.ini" ascii //weight: 1
        $x_1_2 = "Amalgamernes.txt" ascii //weight: 1
        $x_1_3 = "Endothermous.txt" ascii //weight: 1
        $x_1_4 = "Resultatfelternes.ini" ascii //weight: 1
        $x_1_5 = "Udenrigsredaktrerne.txt" ascii //weight: 1
        $x_1_6 = "femtoneskalaer.nat" ascii //weight: 1
        $x_1_7 = "gargol.jpg" ascii //weight: 1
        $x_1_8 = "incapacitation.man" ascii //weight: 1
        $x_1_9 = "tekrusenes.pro" ascii //weight: 1
        $x_1_10 = "venire.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RBU_2147952029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RBU!MTB"
        threat_id = "2147952029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "amariterkursus\\decaesarize\\Eksekverbar" ascii //weight: 1
        $x_1_2 = "Electropotential\\Brombrrenes82\\Proteles" ascii //weight: 1
        $x_1_3 = ".\\Enakteres101.ini" ascii //weight: 1
        $x_1_4 = "#\\dommervagts\\hypogonadism.jpg" ascii //weight: 1
        $x_1_5 = "%unlavished%\\vindue" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SUO_2147952263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SUO!MTB"
        threat_id = "2147952263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\aigialosauridae\\ded.bin" ascii //weight: 1
        $x_1_2 = "\\Threskiornithidae\\Upaaviseligheden.htm" ascii //weight: 1
        $x_1_3 = "99\\udbredte.gif" ascii //weight: 1
        $x_1_4 = "Centripetalkraftens151.mul" ascii //weight: 1
        $x_1_5 = "Itsy.kat" ascii //weight: 1
        $x_1_6 = "Sagndannelses.jay" ascii //weight: 1
        $x_1_7 = "chiropraxis.kil" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RCA_2147952308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RCA!MTB"
        threat_id = "2147952308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Undertrykkelses\\bacalao\\Bipeltate183" ascii //weight: 1
        $x_1_2 = "eeyuch\\Lithotresis215\\tankangrebets" ascii //weight: 1
        $x_1_3 = "99\\onlookers\\qoheleth.ini" ascii //weight: 1
        $x_1_4 = "%relabeler%\\Pibloktos\\uldtrjer" ascii //weight: 1
        $x_1_5 = "-\\Opfindsomste.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SUP_2147952445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SUP!MTB"
        threat_id = "2147952445"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Megapterine109.ini" ascii //weight: 1
        $x_1_2 = "\\produktivitet\\Galvanopsychic" ascii //weight: 1
        $x_1_3 = "\\dowl.txt" ascii //weight: 1
        $x_1_4 = "Opacite.Hom" ascii //weight: 1
        $x_1_5 = "Ddt17.hom" ascii //weight: 1
        $x_1_6 = "arbejdsfunktion.ich" ascii //weight: 1
        $x_1_7 = "kaskades.gle" ascii //weight: 1
        $x_1_8 = "rewrite.whi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_KH_2147952462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.KH!MTB"
        threat_id = "2147952462"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "udvalgsbehandler.skj" ascii //weight: 1
        $x_1_2 = "byorkester.hyp" ascii //weight: 1
        $x_1_3 = "classically.kal" ascii //weight: 1
        $x_1_4 = "rundskaaren.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RCB_2147952650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RCB!MTB"
        threat_id = "2147952650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ubehagelighedernes\\Levitate\\stoppende" ascii //weight: 1
        $x_1_2 = "%bider%\\schnauzers\\udviklingshastighedens" ascii //weight: 1
        $x_1_3 = "%monoprogrammings%\\erma\\undogmatical" ascii //weight: 1
        $x_1_4 = "\\Maaneformrkelse.ini" ascii //weight: 1
        $x_1_5 = "\\spinderokkes\\Gennempletterede.bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SUR_2147952691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SUR!MTB"
        threat_id = "2147952691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\mineralizables\\niggerfish\\Erhvervslederne" ascii //weight: 1
        $x_1_2 = "\\Synaloepha.jpg" ascii //weight: 1
        $x_1_3 = "\\halma.ini" ascii //weight: 1
        $x_1_4 = "\\bippene\\spydspidsens.ini" ascii //weight: 1
        $x_1_5 = "sikkerhedskopierings.jpg" ascii //weight: 1
        $x_1_6 = "\\hstmaskine\\artificialness.ini" ascii //weight: 1
        $x_1_7 = "molekylrt\\skospndets\\troposfrens" ascii //weight: 1
        $x_1_8 = "\\Frerskab\\stningsstrukturens.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_KK_2147952859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.KK!MTB"
        threat_id = "2147952859"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uptower bronteon" ascii //weight: 1
        $x_1_2 = "shaughn paraffinises.exe" ascii //weight: 1
        $x_1_3 = "nonsupportably" ascii //weight: 1
        $x_1_4 = "lnsommeres paucity eurosejren" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RCC_2147952968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RCC!MTB"
        threat_id = "2147952968"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "myrialitre\\forsvenskendes\\falsities" ascii //weight: 1
        $x_1_2 = "%komtessernes%\\Overfaintly\\mouthpiece" ascii //weight: 1
        $x_1_3 = "skrivetilladelserne" ascii //weight: 1
        $x_1_4 = "forenendes conquer lyshaaret" ascii //weight: 1
        $x_1_5 = "navigerede perivenous" ascii //weight: 1
        $x_1_6 = "bigamists logomancy.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SUS_2147953026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SUS!MTB"
        threat_id = "2147953026"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\gniderierne" ascii //weight: 1
        $x_1_2 = "\\medicophysical.txt" ascii //weight: 1
        $x_1_3 = "\\rotteflde\\anlgsjemedene.exe" ascii //weight: 1
        $x_1_4 = "\\philomathy.gif" ascii //weight: 1
        $x_1_5 = "\\astmalgernes\\jagtbdes.bin" ascii //weight: 1
        $x_1_6 = "\\nordeuropiske.exe" ascii //weight: 1
        $x_1_7 = "\\elitekorps.dll" ascii //weight: 1
        $x_1_8 = "\\kaladana\\stablendes.bin" ascii //weight: 1
        $x_1_9 = "Navigabel.jpg" ascii //weight: 1
        $x_1_10 = "bariatrics.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RCD_2147953140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RCD!MTB"
        threat_id = "2147953140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pljning subcuratorship sammensmeltningens" ascii //weight: 1
        $x_1_2 = "skamferes kanalseparation cotangens" ascii //weight: 1
        $x_1_3 = "slimness devourment xiphiplastron" ascii //weight: 1
        $x_1_4 = "saloons.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RCE_2147953317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RCE!MTB"
        threat_id = "2147953317"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Somniloquy158\\Dromedarerne39\\skidesurt" ascii //weight: 1
        $x_1_2 = "%Tegnomraadet%\\overtalelsesevne\\uncourtesy" ascii //weight: 1
        $x_1_3 = "unperiodically unseasonable omregningen" ascii //weight: 1
        $x_1_4 = "stvsugning pantalets ethnobotanist" ascii //weight: 1
        $x_1_5 = "afladningen fertiliserer" ascii //weight: 1
        $x_1_6 = "caliber.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RCF_2147953318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RCF!MTB"
        threat_id = "2147953318"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fringing\\hovedkortene" ascii //weight: 1
        $x_1_2 = "%asian%\\aularian" ascii //weight: 1
        $x_1_3 = "pentylidene agnfiskene" ascii //weight: 1
        $x_1_4 = "blepharoadenitis alloplast anaptychus" ascii //weight: 1
        $x_1_5 = "tilmeldte dbefonterne relish" ascii //weight: 1
        $x_1_6 = "efterbrndere antifoniers.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RCG_2147953518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RCG!MTB"
        threat_id = "2147953518"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "elevcentreredes\\ramified" ascii //weight: 1
        $x_1_2 = "%onagers%\\opholdsstuers\\ddslejernes" ascii //weight: 1
        $x_1_3 = "\\kemikalies\\jamnia.lnk" ascii //weight: 1
        $x_1_4 = "\\tjrnekrattet\\deheathenize.ini" ascii //weight: 1
        $x_1_5 = "Nonplatitudinously.ene" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SUT_2147953583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SUT!MTB"
        threat_id = "2147953583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Roesukkerets23\\raught" ascii //weight: 1
        $x_1_2 = "Acetoxyphthalide124.txt" ascii //weight: 1
        $x_1_3 = "Artet45.cat" ascii //weight: 1
        $x_1_4 = "Forskningsprojekters102.jpg" ascii //weight: 1
        $x_1_5 = "Insuppressibility.ini" ascii //weight: 1
        $x_1_6 = "efterbehandlende.jpg" ascii //weight: 1
        $x_1_7 = "veltilfredheden.avl" ascii //weight: 1
        $x_1_8 = "\\befallen\\Prislags.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SUV_2147953612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SUV!MTB"
        threat_id = "2147953612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\vandforsyningernes\\overobediently\\cauboge" ascii //weight: 1
        $x_1_2 = "\\nednormeringens\\hayburner.ini" ascii //weight: 1
        $x_1_3 = "\\bralrende\\audings.htm" ascii //weight: 1
        $x_1_4 = "\\fewness\\hypotesens.dll" ascii //weight: 1
        $x_1_5 = "\\Forbigangen162\\grundvandsbeskyttelsens.jpg" ascii //weight: 1
        $x_1_6 = "\\tndingsnglerne" ascii //weight: 1
        $x_1_7 = "\\contignate.lnk" ascii //weight: 1
        $x_1_8 = "Preutilizing49.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SUW_2147953627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SUW!MTB"
        threat_id = "2147953627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\quippy.txt" ascii //weight: 1
        $x_1_2 = "\\vestvggens.htm" ascii //weight: 1
        $x_1_3 = "\\style.Nig" ascii //weight: 1
        $x_1_4 = "\\threshel\\trimellitic.ini" ascii //weight: 1
        $x_1_5 = "Valmuefrs.Ove" ascii //weight: 1
        $x_1_6 = "Afprik.txt" ascii //weight: 1
        $x_1_7 = "Centraliseret.jpg" ascii //weight: 1
        $x_1_8 = "Decarbonylating.ini" ascii //weight: 1
        $x_1_9 = "Tedesca.jpg" ascii //weight: 1
        $x_1_10 = "opbevaringskapaciteternes.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RCH_2147953648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RCH!MTB"
        threat_id = "2147953648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-\\anderledestnkende\\convival" ascii //weight: 1
        $x_1_2 = "honeyhearted\\Earthslide78\\susser" ascii //weight: 1
        $x_1_3 = "88\\Larrup\\Accursedly.zip" ascii //weight: 1
        $x_1_4 = "DST Systems, Inc." ascii //weight: 1
        $x_1_5 = "E.W. Scripps Company" ascii //weight: 1
        $x_1_6 = "rouleauers.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RCI_2147953742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RCI!MTB"
        threat_id = "2147953742"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gradiometer\\juloid\\sodalithite" ascii //weight: 1
        $x_1_2 = "%harvendes%\\lykkeflelsen" ascii //weight: 1
        $x_1_3 = "Anadarko Petroleum Corporation" ascii //weight: 1
        $x_1_4 = "Bristol-Myers Squibb Company" ascii //weight: 1
        $x_1_5 = "urpremieres.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RCJ_2147953845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RCJ!MTB"
        threat_id = "2147953845"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\protesen\\kendingssignaler" ascii //weight: 1
        $x_1_2 = "\\scientolism\\oplsningernes.bin" ascii //weight: 1
        $x_1_3 = "%Ordvekslingens%\\inadvertant\\billardkuglerne" ascii //weight: 1
        $x_1_4 = "Fremtidsforskeren35.ini" ascii //weight: 1
        $x_1_5 = "Quanta Services Inc." ascii //weight: 1
        $x_1_6 = "pachyglossous.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_GuLoader_RCK_2147953924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RCK!MTB"
        threat_id = "2147953924"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "coupbcerne" ascii //weight: 1
        $x_1_2 = "sygeplejeskolens staphyloplastic kaffebords" ascii //weight: 1
        $x_1_3 = "registreringsafgiftens xylidine.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RCL_2147953948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RCL!MTB"
        threat_id = "2147953948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\gehejmeraadernes\\Inconscience62" ascii //weight: 1
        $x_1_2 = "%Club%\\Racisten239\\ltningens" ascii //weight: 1
        $x_1_3 = "embedseksamens taygeta isazoxy" ascii //weight: 1
        $x_1_4 = "horisontallinie" ascii //weight: 1
        $x_1_5 = "velstandssamfundet" ascii //weight: 1
        $x_1_6 = "erotic annizettes.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RCM_2147954478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RCM!MTB"
        threat_id = "2147954478"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "malihinis prydelser pleurocentral" ascii //weight: 1
        $x_1_2 = "konstruktionsmaaden" ascii //weight: 1
        $x_1_3 = "sejrs" ascii //weight: 1
        $x_1_4 = "arealberegningerne knleddet.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SUX_2147954479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SUX!MTB"
        threat_id = "2147954479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\cerianthoid\\veneral" ascii //weight: 1
        $x_1_2 = "\\Ordrig\\Overindustrialized.exe" ascii //weight: 1
        $x_1_3 = "Dagvagterne70.met" ascii //weight: 1
        $x_1_4 = "Nazarenes177.ita" ascii //weight: 1
        $x_1_5 = "Radikalerne.txt" ascii //weight: 1
        $x_1_6 = "Rubijervine207.jpg" ascii //weight: 1
        $x_1_7 = "beguilingly.txt" ascii //weight: 1
        $x_1_8 = "\\Specialordbog\\Hensover" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RCN_2147954725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RCN!MTB"
        threat_id = "2147954725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "astrolabical stikprve" ascii //weight: 1
        $x_1_2 = "preendorsement snuptagets uberously" ascii //weight: 1
        $x_1_3 = "eavesdrip draftily stridsksernes" ascii //weight: 1
        $x_1_4 = "park semanticist" ascii //weight: 1
        $x_1_5 = "typhoemia apehood.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RCO_2147954837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RCO!MTB"
        threat_id = "2147954837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "depending dyds moorage" ascii //weight: 1
        $x_1_2 = "ristedes authoritarianism" ascii //weight: 1
        $x_1_3 = "dt talehandlinger" ascii //weight: 1
        $x_1_4 = "oleaginous.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RCP_2147954948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RCP!MTB"
        threat_id = "2147954948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#\\Clientless12\\afgnavedes" ascii //weight: 1
        $x_1_2 = "5\\Sunblock41\\scabish.ini" ascii //weight: 1
        $x_1_3 = "hvidtekalkens inkwood fiddlewood" ascii //weight: 1
        $x_1_4 = "strigae chromatospheric" ascii //weight: 1
        $x_1_5 = "muskatens" ascii //weight: 1
        $x_1_6 = "advarslerne.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SUY_2147954949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SUY!MTB"
        threat_id = "2147954949"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\hotcha\\Emptiness.bin" ascii //weight: 1
        $x_1_2 = "\\Ultimates67\\overyoung.txt" ascii //weight: 1
        $x_1_3 = "\\Monteredes" ascii //weight: 1
        $x_1_4 = "\\copolymerises\\frostbitten.gif" ascii //weight: 1
        $x_1_5 = "\\deaminize.jpg" ascii //weight: 1
        $x_1_6 = "\\tvrsummerne.htm" ascii //weight: 1
        $x_1_7 = "Exsiccating.bry" ascii //weight: 1
        $x_1_8 = "Offentlighedsfaserne.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SUZ_2147954963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SUZ!MTB"
        threat_id = "2147954963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Antiburgher.bul" ascii //weight: 1
        $x_1_2 = "Bygningsfejlenes222.dis" ascii //weight: 1
        $x_1_3 = "Eneboerne.kan" ascii //weight: 1
        $x_1_4 = "Gummistvlens.dem" ascii //weight: 1
        $x_1_5 = "Overstrmmedes.jen" ascii //weight: 1
        $x_1_6 = "Subcompleteness181.fil" ascii //weight: 1
        $x_1_7 = "rhynchocephalia.eas" ascii //weight: 1
        $x_1_8 = "upbuoying.skr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SVA_2147955222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SVA!MTB"
        threat_id = "2147955222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\outstander\\topopolitan.jpg" ascii //weight: 1
        $x_1_2 = "Basemodem129.opv" ascii //weight: 1
        $x_1_3 = "Indlaans43.daa" ascii //weight: 1
        $x_1_4 = "Tristichous.tal" ascii //weight: 1
        $x_1_5 = "dokumentargruppe.cal" ascii //weight: 1
        $x_1_6 = "firearms.pyr" ascii //weight: 1
        $x_1_7 = "hemihydrosis.orl" ascii //weight: 1
        $x_1_8 = "\\Direktionen218\\Flowerpecker.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RCS_2147955312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RCS!MTB"
        threat_id = "2147955312"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fortinnedes maps konkretiserende" ascii //weight: 1
        $x_1_2 = "kbmandsregning" ascii //weight: 1
        $x_1_3 = "philotheistic" ascii //weight: 1
        $x_1_4 = "spinkede.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RCT_2147955423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RCT!MTB"
        threat_id = "2147955423"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\hyperaesthete\\Eskimologisk\\centricae" ascii //weight: 1
        $x_1_2 = "%ledgeman%\\tilbagerapporteringer" ascii //weight: 1
        $x_1_3 = "\\Acerbate\\Storpolitiskes" ascii //weight: 1
        $x_1_4 = "overconscientiousness shivoos" ascii //weight: 1
        $x_1_5 = "slounger sar" ascii //weight: 1
        $x_1_6 = "elektronikfirmaet.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SVB_2147955424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SVB!MTB"
        threat_id = "2147955424"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\yogis\\apoteksassistenterne" ascii //weight: 1
        $x_1_2 = "\\paaklagede\\budgetrodet.ini" ascii //weight: 1
        $x_1_3 = "\\usknne.zip" ascii //weight: 1
        $x_1_4 = "Gigantisk.txt" ascii //weight: 1
        $x_1_5 = "Longwinded.qua" ascii //weight: 1
        $x_1_6 = "interimskvitteringens.mak" ascii //weight: 1
        $x_1_7 = "ridebanespringning.jpg" ascii //weight: 1
        $x_1_8 = "\\geografiske.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SD_2147955438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SD!MTB"
        threat_id = "2147955438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\coroplasty.dll" ascii //weight: 1
        $x_1_2 = "glathvlen.bat" ascii //weight: 1
        $x_1_3 = "hylarchical\\subtill.bin" ascii //weight: 1
        $x_1_4 = "advokatfirmaets\\skiddoo\\listede" ascii //weight: 1
        $x_1_5 = "kastepiles.mic" ascii //weight: 1
        $x_1_6 = "kraftvrkernes.cir" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SD_2147955438_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SD!MTB"
        threat_id = "2147955438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lese palmas stemmeridsens" ascii //weight: 1
        $x_1_2 = "staphylinideous smrtyvenes frstemand" ascii //weight: 1
        $x_1_3 = "nondistillable bogbinderens.exe" ascii //weight: 1
        $x_1_4 = "fluoric.hel" ascii //weight: 1
        $x_1_5 = "\\servicecheferne.htm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SD_2147955438_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SD!MTB"
        threat_id = "2147955438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bollerne rejuggle virksomhedsskatterne" ascii //weight: 1
        $x_1_2 = "centralvarmeapparatets underbemandendes circumnavigable" ascii //weight: 1
        $x_1_3 = "bortkomsts.exe" ascii //weight: 1
        $x_1_4 = "folketingstidendernes forgeful slentrendes" ascii //weight: 1
        $x_1_5 = "brachygraphical" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SVC_2147955957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SVC!MTB"
        threat_id = "2147955957"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\obside\\Magneter.ini" ascii //weight: 1
        $x_1_2 = "lavprisvarehuse.txt" ascii //weight: 1
        $x_1_3 = "\\frafaldsprocent.jpg" ascii //weight: 1
        $x_1_4 = "Achondritic102.fim" ascii //weight: 1
        $x_1_5 = "Astrakan.txt" ascii //weight: 1
        $x_1_6 = "Beglooms.out" ascii //weight: 1
        $x_1_7 = "Brysthules177.ekv" ascii //weight: 1
        $x_1_8 = "Eksproprieringsplan.stj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SVD_2147956130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SVD!MTB"
        threat_id = "2147956130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\tidsbestemmer.ini" ascii //weight: 1
        $x_1_2 = "\\Iconvert\\photocrayon\\Stercorite" ascii //weight: 1
        $x_1_3 = "\\Auditors244\\Irradiancy.jpg" ascii //weight: 1
        $x_1_4 = "\\tilsynekomstens\\guachipilin" ascii //weight: 1
        $x_1_5 = "\\unfinancial\\Brevvekslede.htm" ascii //weight: 1
        $x_1_6 = "\\kovarer\\signeres.ini" ascii //weight: 1
        $x_1_7 = "\\wifelet\\Sygeplejeassistents.zip" ascii //weight: 1
        $x_1_8 = "\\renskrifter.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RCV_2147956141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RCV!MTB"
        threat_id = "2147956141"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yuckle regelfaststtelserne seducers" ascii //weight: 1
        $x_1_2 = "mavelandingen praktikkernes" ascii //weight: 1
        $x_1_3 = "entitet dityramber" ascii //weight: 1
        $x_1_4 = "mainframes tyrsenoi" ascii //weight: 1
        $x_1_5 = "tapskruernes loliginidae.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RCW_2147956214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RCW!MTB"
        threat_id = "2147956214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "merkantiliseringerne\\iras\\alfedans" ascii //weight: 1
        $x_1_2 = "proterandrously\\Muldede\\" ascii //weight: 1
        $x_1_3 = "\\breddeminutternes.ini" ascii //weight: 1
        $x_1_4 = "%choriocapillaris%\\listeriosis" ascii //weight: 1
        $x_1_5 = "Abortgrupper164\\Traenet.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SVE_2147956337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SVE!MTB"
        threat_id = "2147956337"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\romantikers\\vaporizes" ascii //weight: 1
        $x_1_2 = "\\effervescences.bin" ascii //weight: 1
        $x_1_3 = "\\gytling.gif" ascii //weight: 1
        $x_1_4 = "Kejsertankers.sch" ascii //weight: 1
        $x_1_5 = "\\klasseundervisningerne.txt" ascii //weight: 1
        $x_1_6 = "\\Pogonophoran\\debatteateret.jpg" ascii //weight: 1
        $x_1_7 = "\\Reactionarism.bin" ascii //weight: 1
        $x_1_8 = "\\Tonguelike.zip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RCX_2147956395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RCX!MTB"
        threat_id = "2147956395"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "littlin lagkagens" ascii //weight: 1
        $x_1_2 = "quebec spartaneres" ascii //weight: 1
        $x_1_3 = "lgdommmerordnings" ascii //weight: 1
        $x_1_4 = "vamooses.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SVF_2147956396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SVF!MTB"
        threat_id = "2147956396"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\superfosfaters\\ejendomsskatterne\\promammalian" ascii //weight: 1
        $x_1_2 = "\\Joram.ini" ascii //weight: 1
        $x_1_3 = "redelighed\\exposing" ascii //weight: 1
        $x_1_4 = "Praediality.sta" ascii //weight: 1
        $x_1_5 = "\\vexillation\\havelaage.txt" ascii //weight: 1
        $x_1_6 = "\\decigrammet\\Hamadryas.zip" ascii //weight: 1
        $x_1_7 = "\\Sognenes\\radiologens.lnk" ascii //weight: 1
        $x_1_8 = "\\talesprogets.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RCY_2147956446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RCY!MTB"
        threat_id = "2147956446"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "skidteriets\\Tretommersm\\" ascii //weight: 1
        $x_1_2 = "%Bryophyte%\\Gilt\\basalters" ascii //weight: 1
        $x_1_3 = "kaolin haandsbreddernes" ascii //weight: 1
        $x_1_4 = "syerskes timelrernes" ascii //weight: 1
        $x_1_5 = "servobremse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RCZ_2147956620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RCZ!MTB"
        threat_id = "2147956620"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\micelles\\kuglerums" ascii //weight: 1
        $x_1_2 = "ledelsesmssiges\\quinary\\ponchoers" ascii //weight: 1
        $x_1_3 = "99\\kassebeholdningernes.ini" ascii //weight: 1
        $x_1_4 = "%consumerism%\\gaussfilterfunktionernes" ascii //weight: 1
        $x_1_5 = "6\\Remonstrant230\\krigsfrelsernes.exe" ascii //weight: 1
        $x_1_6 = "88\\Chemisetternes.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SVG_2147956708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SVG!MTB"
        threat_id = "2147956708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Jonathanization\\toningens.htm" ascii //weight: 1
        $x_1_2 = "\\kritikers.ini" ascii //weight: 1
        $x_1_3 = "judiciality.exe" ascii //weight: 1
        $x_1_4 = "\\Blodprocenterne247\\maffick.bin" ascii //weight: 1
        $x_1_5 = "\\journeyers\\ilmarcher.htm" ascii //weight: 1
        $x_1_6 = "\\Pledgors58\\Nx.ini" ascii //weight: 1
        $x_1_7 = "Austenitizing.gym" ascii //weight: 1
        $x_1_8 = "Populously.ypp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RDA_2147956766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RDA!MTB"
        threat_id = "2147956766"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "brudepars\\etaarsfdselsdagens\\dksbaaden" ascii //weight: 1
        $x_1_2 = "%Bevomited25%\\Markedsudvikling122\\printerskrift" ascii //weight: 1
        $x_1_3 = "7\\necessism\\pectosase.lnk" ascii //weight: 1
        $x_1_4 = "88\\rectangle\\Brasier.ini" ascii //weight: 1
        $x_1_5 = "((\\gnaskerierne\\glemmebog.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SVH_2147956767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SVH!MTB"
        threat_id = "2147956767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "earbob indrmmelsers" ascii //weight: 1
        $x_1_2 = "stuehusets.exe" ascii //weight: 1
        $x_1_3 = "faresignalers" ascii //weight: 1
        $x_1_4 = "proborrowing moskiqen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RDB_2147956878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RDB!MTB"
        threat_id = "2147956878"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "johannas affedtningernes lingams" ascii //weight: 1
        $x_1_2 = "argumentation compliable" ascii //weight: 1
        $x_1_3 = "uforsigtigheders lufberry.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SVI_2147956957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SVI!MTB"
        threat_id = "2147956957"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\gennempljet\\Bryllupsdag" ascii //weight: 1
        $x_1_2 = "\\Blokningens\\ubarmhjertigheden.gif" ascii //weight: 1
        $x_1_3 = "Derogative.Unr" ascii //weight: 1
        $x_1_4 = "Driftsbidrag.ini" ascii //weight: 1
        $x_1_5 = "Hiccoughs5.jpg" ascii //weight: 1
        $x_1_6 = "Proport.reg" ascii //weight: 1
        $x_1_7 = "\\Kandelabrene\\Tirernes97\\Paaseende" ascii //weight: 1
        $x_1_8 = "hovedstadsomraadets.pot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RDC_2147957057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RDC!MTB"
        threat_id = "2147957057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "recontracting\\Saxonical243\\loch" ascii //weight: 1
        $x_1_2 = "%formodede%\\inacquaintance" ascii //weight: 1
        $x_1_3 = "6\\adinidan\\funned.ini" ascii //weight: 1
        $x_1_4 = "mbaya skrupsentimentale" ascii //weight: 1
        $x_1_5 = "skipping klaringens.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RDD_2147957138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RDD!MTB"
        threat_id = "2147957138"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "frittens eumolpus" ascii //weight: 1
        $x_1_2 = "riposteret" ascii //weight: 1
        $x_1_3 = "oplsningsmiddel historicising.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SVJ_2147957147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SVJ!MTB"
        threat_id = "2147957147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "endopolyploidy" ascii //weight: 1
        $x_1_2 = "inorganity grotesque oatcakes" ascii //weight: 1
        $x_1_3 = "pretired" ascii //weight: 1
        $x_1_4 = "talmudization.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RDE_2147957341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RDE!MTB"
        threat_id = "2147957341"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "evadtre bdle" ascii //weight: 1
        $x_1_2 = "lianer lsternes" ascii //weight: 1
        $x_1_3 = "ledtoget singularisers superinjustice" ascii //weight: 1
        $x_1_4 = "anernes sniddle.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SVL_2147957442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SVL!MTB"
        threat_id = "2147957442"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\enrail\\kvgavl\\kamuflage" ascii //weight: 1
        $x_1_2 = "\\multidigitate\\Stanching179.exe" ascii //weight: 1
        $x_1_3 = "\\Seemed139.jpg" ascii //weight: 1
        $x_1_4 = "\\Neochristianity.Reg32" ascii //weight: 1
        $x_1_5 = "Arkfderkontrollen.ini" ascii //weight: 1
        $x_1_6 = "Discountpriser.dio" ascii //weight: 1
        $x_1_7 = "\\Smilehuller\\Trephining\\Livritkldt" ascii //weight: 1
        $x_1_8 = "\\Forhandlerseminarerne\\Emigrationers" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RDF_2147957634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RDF!MTB"
        threat_id = "2147957634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "udvirkedes" ascii //weight: 1
        $x_1_2 = "stillelsningsprven lovregelen haandvrksraadets" ascii //weight: 1
        $x_1_3 = "insekternes capripede" ascii //weight: 1
        $x_1_4 = "reoxidize urovarslings.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RDG_2147957727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RDG!MTB"
        threat_id = "2147957727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "terapiassistenten" ascii //weight: 1
        $x_1_2 = "skvisningernes gruppediskussionens exorcistic" ascii //weight: 1
        $x_1_3 = "solanders kontorassistenten zedoaries" ascii //weight: 1
        $x_1_4 = "bortkastningerne" ascii //weight: 1
        $x_1_5 = "resgstens.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RDH_2147957991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RDH!MTB"
        threat_id = "2147957991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\stiks\\knosp" ascii //weight: 1
        $x_1_2 = "acalycine\\unsalvaged\\qindars" ascii //weight: 1
        $x_1_3 = "%ophovnede%\\tjaele\\Eleemosynar" ascii //weight: 1
        $x_1_4 = "internuncially.ini" ascii //weight: 1
        $x_1_5 = "\\Sealike18\\colorfully.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SVP_2147957999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SVP!MTB"
        threat_id = "2147957999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\nattergalene\\hovedmedvirkendes\\informationssgning" ascii //weight: 1
        $x_1_2 = "\\pindebrnde\\Sangerfest101.lnk" ascii //weight: 1
        $x_1_3 = "\\occidentalized\\Ufordragelighedens.ini" ascii //weight: 1
        $x_1_4 = "\\ringsteder\\dyrlgernes.jpg" ascii //weight: 1
        $x_1_5 = "\\Slbningens120.lnk" ascii //weight: 1
        $x_1_6 = "\\amperemetrets.bin" ascii //weight: 1
        $x_1_7 = "\\svrdliljer.htm" ascii //weight: 1
        $x_1_8 = "\\arealforhold\\bladgrnt.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SVO_2147958000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SVO!MTB"
        threat_id = "2147958000"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Blanderen.lnk" ascii //weight: 1
        $x_1_2 = "\\trkasserne\\scamel.jpg" ascii //weight: 1
        $x_1_3 = "\\Nonsolubly\\hotmouthed.ini" ascii //weight: 1
        $x_1_4 = "\\dishwasher.ini" ascii //weight: 1
        $x_1_5 = "\\Sealike18\\colorfully.jpg" ascii //weight: 1
        $x_1_6 = "\\intercompare.zip" ascii //weight: 1
        $x_1_7 = "Arrogates215.dor" ascii //weight: 1
        $x_1_8 = "Spiritusbeskatningen240.anu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SVQ_2147958118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SVQ!MTB"
        threat_id = "2147958118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Unbetterable98\\smrgaasen" ascii //weight: 1
        $x_1_2 = "\\Internalization65\\Unchatteled.jpg" ascii //weight: 1
        $x_1_3 = "\\Acrostolion47\\Semipanic179.lnk" ascii //weight: 1
        $x_1_4 = "Bajonetfatninger.don" ascii //weight: 1
        $x_1_5 = "Haandtaskens.bev" ascii //weight: 1
        $x_1_6 = "Intrafistular.sel" ascii //weight: 1
        $x_1_7 = "Patruljefrernes.ini" ascii //weight: 1
        $x_1_8 = "heteroseksualitets.sma" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RDI_2147958136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RDI!MTB"
        threat_id = "2147958136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\hvsendes\\spinescence\\Mimosis39" ascii //weight: 1
        $x_1_2 = "vandreren\\unhating\\Filigera" ascii //weight: 1
        $x_1_3 = "shepstare" ascii //weight: 1
        $x_1_4 = "gymnogynous microphonic" ascii //weight: 1
        $x_1_5 = "piscifauna fodgngerfelternes" ascii //weight: 1
        $x_1_6 = "murermesters.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RDJ_2147958158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RDJ!MTB"
        threat_id = "2147958158"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\tommelfingerneglenes\\Punktafgifternes" ascii //weight: 1
        $x_1_2 = "\\Regalist129\\sues" ascii //weight: 1
        $x_1_3 = "\\winnowill\\Falkonerernes.ini" ascii //weight: 1
        $x_1_4 = "%Belurende%\\indebaarnes" ascii //weight: 1
        $x_1_5 = "studiested adamitical" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RDK_2147958246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RDK!MTB"
        threat_id = "2147958246"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dorsicommissure khaldian" ascii //weight: 1
        $x_1_2 = "kaleege warmest" ascii //weight: 1
        $x_1_3 = "praktikabel forskningsarbejdernes crowtoe" ascii //weight: 1
        $x_1_4 = "bemercy goatsbane fedtstoffernes" ascii //weight: 1
        $x_1_5 = "parameterfremstillingens.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SVR_2147958247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SVR!MTB"
        threat_id = "2147958247"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Bolivianerens57.bin" ascii //weight: 1
        $x_1_2 = "\\lommetrklders.htm" ascii //weight: 1
        $x_1_3 = "\\ultraselect.ini" ascii //weight: 1
        $x_1_4 = "\\advance\\Insolvente74.jpg" ascii //weight: 1
        $x_1_5 = "\\reperplex.jpg" ascii //weight: 1
        $x_1_6 = "\\sideless\\formuefllesskabernes.txt" ascii //weight: 1
        $x_1_7 = "\\censusses.txt" ascii //weight: 1
        $x_1_8 = "\\saraband\\Udtalelsen223.lnk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RDL_2147958291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RDL!MTB"
        threat_id = "2147958291"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "underkommandoer" ascii //weight: 1
        $x_1_2 = "courser elef" ascii //weight: 1
        $x_1_3 = "steril squeg dumpiest" ascii //weight: 1
        $x_1_4 = "festivities" ascii //weight: 1
        $x_1_5 = "troligeres skovmandshilsenen.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SVT_2147958403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SVT!MTB"
        threat_id = "2147958403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "alumnol unbirdly" ascii //weight: 1
        $x_1_2 = "pseudoeugenics manager" ascii //weight: 1
        $x_1_3 = "bordellets harleian.exe" ascii //weight: 1
        $x_1_4 = "slmningernes bedmate trosiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RDM_2147958456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RDM!MTB"
        threat_id = "2147958456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Sukkerskaalen\\Kilohertzen59\\Cares26" ascii //weight: 1
        $x_1_2 = "fjortenaarsfdselsdagen\\spirals" ascii //weight: 1
        $x_1_3 = "\\kantates\\tilbagestaaende.txt" ascii //weight: 1
        $x_1_4 = "\\Lacunaria17\\ombygningsarbejdernes.exe" ascii //weight: 1
        $x_1_5 = "%elefants%\\tetradesmus\\indlullet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SVU_2147958462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SVU!MTB"
        threat_id = "2147958462"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Forskaanelsen35\\mangedobling.gif" ascii //weight: 1
        $x_1_2 = "Sprognormeringernes\\Uninstall\\nonorganically" ascii //weight: 1
        $x_1_3 = "\\Calcitrate\\gennemspiller.jpg" ascii //weight: 1
        $x_1_4 = "\\franarrendes.ini" ascii //weight: 1
        $x_1_5 = "\\begravelsesmyndigheder\\Fordummendes.bin" ascii //weight: 1
        $x_1_6 = "\\Lovbundnes\\frokoststuerne" ascii //weight: 1
        $x_1_7 = "Servitutbelagtes\\quindene" ascii //weight: 1
        $x_1_8 = "Damoklessvrdet76.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RDN_2147958569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RDN!MTB"
        threat_id = "2147958569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "respirer\\udlosse\\kowtower" ascii //weight: 1
        $x_1_2 = "rigescent\\advokatbestalling\\phyllostome" ascii //weight: 1
        $x_1_3 = "%smedning%\\Benpibens104" ascii //weight: 1
        $x_1_4 = "\\atomorganisation\\kolliderende.jpg" ascii //weight: 1
        $x_1_5 = "\\hjfjeldssoles\\Skeletonian180.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RDO_2147958655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RDO!MTB"
        threat_id = "2147958655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NiSource Inc" ascii //weight: 1
        $x_1_2 = "Airborne, Inc." ascii //weight: 1
        $x_1_3 = "cheerer sklmske.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RDP_2147958740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RDP!MTB"
        threat_id = "2147958740"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\gurgulation\\buffooneries\\converterne" ascii //weight: 1
        $x_1_2 = "heightens\\engangsskat\\" ascii //weight: 1
        $x_1_3 = "\\coappear\\Hagboat.bin" ascii //weight: 1
        $x_1_4 = "\\ared\\Lemmernes.ini" ascii //weight: 1
        $x_1_5 = "\\Wilderland\\hemiataxy.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RDP_2147958740_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RDP!MTB"
        threat_id = "2147958740"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Chutzpas141\\Chargeably31" ascii //weight: 1
        $x_1_2 = "\\subobscureness\\Groundward.ini" ascii //weight: 1
        $x_1_3 = "\\Tekstndringerne.bin" ascii //weight: 1
        $x_1_4 = "%frelsersoldat%\\Hornmusik\\aviserer" ascii //weight: 1
        $x_1_5 = "\\interpellerendes.jpg" ascii //weight: 1
        $x_1_6 = "\\fjerkrfarme\\sikstus.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SVW_2147958741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SVW!MTB"
        threat_id = "2147958741"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Overinsistent\\debatartikler" ascii //weight: 1
        $x_1_2 = "\\rustkamrenes.ini" ascii //weight: 1
        $x_1_3 = "\\skrivearbejdet\\forbandet.ini" ascii //weight: 1
        $x_1_4 = "\\Nocten\\eclectic.zip" ascii //weight: 1
        $x_1_5 = "\\behandlingsmetoden\\Bankfunktionrers231.dll" ascii //weight: 1
        $x_1_6 = "\\Lsladelser\\Cystotrachelotomy.bin" ascii //weight: 1
        $x_1_7 = "\\tndere\\plasters.ini" ascii //weight: 1
        $x_1_8 = "\\gwinter.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RDQ_2147958889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RDQ!MTB"
        threat_id = "2147958889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Level 3 Communications Inc." ascii //weight: 1
        $x_1_2 = "VirtualDJ" ascii //weight: 1
        $x_1_3 = "Beepa Pty Ltd" ascii //weight: 1
        $x_1_4 = "scarabaeus.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RDR_2147958910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RDR!MTB"
        threat_id = "2147958910"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uvanligereomk" ascii //weight: 1
        $x_1_2 = "NONSTIC" ascii //weight: 1
        $x_1_3 = "Meousgavebo" ascii //weight: 1
        $x_1_4 = "unawarelymed" ascii //weight: 1
        $x_1_5 = "INSTRUKTIONS" ascii //weight: 1
        $x_1_6 = "Anti60" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SVX_2147959002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SVX!MTB"
        threat_id = "2147959002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Dehydreringers74.zip" ascii //weight: 1
        $x_1_2 = "\\Porcelainizing.ini" ascii //weight: 1
        $x_1_3 = "\\siklinger.ini" ascii //weight: 1
        $x_1_4 = "\\Friturekurvene.zip" ascii //weight: 1
        $x_1_5 = "\\surcrue\\mercis.bin" ascii //weight: 1
        $x_1_6 = "\\romboiden\\Bedims79.htm" ascii //weight: 1
        $x_1_7 = "\\gevindene\\northwestern.ini" ascii //weight: 1
        $x_1_8 = "\\dukhobor\\udliggerbaad.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RDS_2147959009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RDS!MTB"
        threat_id = "2147959009"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "opkaldssekvensernes\\adfrdsformers" ascii //weight: 1
        $x_1_2 = "%prepromised%\\integritetsregels\\tatoverede" ascii //weight: 1
        $x_1_3 = "astrophotometer forfrem skolehjemmenes" ascii //weight: 1
        $x_1_4 = "udfoldelsen ansttelsesperiode" ascii //weight: 1
        $x_1_5 = "ataxiaphasia" ascii //weight: 1
        $x_1_6 = "appulses.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_SVY_2147959084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.SVY!MTB"
        threat_id = "2147959084"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\risikobegrebs" ascii //weight: 1
        $x_1_2 = "\\therapy.txt" ascii //weight: 1
        $x_1_3 = "\\joltless.txt" ascii //weight: 1
        $x_1_4 = "\\Bliders147\\foresight.ini" ascii //weight: 1
        $x_1_5 = "\\beldringe.ini" ascii //weight: 1
        $x_1_6 = "\\kloakeringsomraaders\\Cloze201.ini" ascii //weight: 1
        $x_1_7 = "\\Phosphonuclease.exe" ascii //weight: 1
        $x_1_8 = "kronprinserne.pro" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GuLoader_RDT_2147959120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GuLoader.RDT!MTB"
        threat_id = "2147959120"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7\\putlogs\\hypocistis.dll" ascii //weight: 1
        $x_1_2 = "leonardo\\Pseudoarticulation158\\corynid" ascii //weight: 1
        $x_1_3 = "arimathaean" ascii //weight: 1
        $x_1_4 = "heterochromosome forholdsvist uddifferentieringer" ascii //weight: 1
        $x_1_5 = "bortkaster pharmacologically.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

