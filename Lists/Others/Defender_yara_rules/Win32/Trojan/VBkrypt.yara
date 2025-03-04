rule Trojan_Win32_VBKrypt_AA_2147745187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.AA!MTB"
        threat_id = "2147745187"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 8b c6 99 f7 f9 8b 45 ac 66 33 1c 50 8b 4d 08 8b 31 8d 55 d0 52 ff 15 ?? ?? ?? ?? 8b 4d 08 8b 11 2b 42 14 8b 4e 0c 88 1c 01 8d 4d 84}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c8 8b c6 99 f7 f9 8b 45 ac 66 33 1c 50 8b 4d 0c 8b 31 8d 55 d0 52 ff 15 ?? ?? ?? ?? 8b 4d 0c 8b 11 2b 42 14 8b 4e 0c 88 1c 01 8d 4d 84}  //weight: 1, accuracy: Low
        $x_1_3 = "\\dracullCalendar.pdf" wide //weight: 1
        $x_1_4 = "_ford.jpg" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_VBKrypt_AB_2147745432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.AB!MTB"
        threat_id = "2147745432"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 d8 8b 52 0c 8b 49 0c 8a 14 1a 8b 7d 94 32 14 39 83 c6 01 88 14 01 8b 45 e8 0f 80 ?? ?? ?? ?? 3b f0 7e 02 33 f6 8b 45 e4 83 c0 01 0f 80 ?? ?? ?? ?? 89 45 e4 e9 ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = "Funcxcvcxvxc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_GG_2147745517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.GG!MTB"
        threat_id = "2147745517"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 8b c6 99 f7 f9 8b 45 ac 66 33 [0-2] 8b 4d ?? 8b 31 8d 55 d0 52 ff 15 [0-4] 8b 4d ?? 8b 11 2b 42 14 8b 4e 0c 88 1c 01 8d 4d 84 ff 15 [0-35] 89 85 [0-4] 83 bd [0-4] 00}  //weight: 1, accuracy: Low
        $x_1_2 = "\\Darins.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_GA_2147745518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.GA!MTB"
        threat_id = "2147745518"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 8b c3 03 ca 99 f7 f9 8d 45 ?? 50 8b da ff 15 [0-4] 8b 8d [0-4] 8a 14 08 32 da 8d 55 ?? 52 ff 15 [0-4] 8b 8d [0-4] 8d 55 ?? 52 88 1c 08 8d 45 ?? 50 6a ?? ff 15 [0-4] 8b 4d ?? b8 [0-4] 83 c4 ?? 03 c8 89 4d}  //weight: 1, accuracy: Low
        $x_1_2 = "BMGDocumenter" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_CA_2147745621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.CA!eml"
        threat_id = "2147745621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cacIOTTONalibera" wide //weight: 1
        $x_1_2 = "controrAX.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_GB_2147745634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.GB!MTB"
        threat_id = "2147745634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 8b c3 03 ca 99 [0-6] f7 f9 8d 45 ?? 50 8b da ff 15 [0-4] 8b 95 [0-4] 33 c9 8a 0c 10 33 cb ff 15 [0-4] 8a d8 8d 45 ?? 50 ff 15 [0-4] 8b 8d [0-4] 8d 55 ?? 52 88 1c 08 8d 45 ?? 50 6a 02 ff 15 [0-4] b8 [0-4] 83 c4 ?? 66 03 45 ec}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c8 8b c3 03 ca 99 f7 f9 8d 45 ?? 50 8b da ff 15 [0-4] 8b [0-8] 32 ?? 8d [0-3] ff 15 [0-4] 8b 8d [0-4] 8d 55 ?? 52 88 1c 08 8d 45 ?? 50 6a 02 ff 15 [0-7] b8 [0-4] 83 c4 0c 96 00 33 db 8a 1c 0a 8d 55 b4 52 ff d7 0f bf 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_VBKrypt_AC_2147749244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.AC!MTB"
        threat_id = "2147749244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 ff 34 1f}  //weight: 1, accuracy: High
        $x_1_2 = {31 34 24 e9}  //weight: 1, accuracy: High
        $x_1_3 = {83 c4 04 89 14 18}  //weight: 1, accuracy: High
        $x_1_4 = {83 c4 04 83 fb 00 0f 85 ?? ?? ff ff e9 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_AD_2147750146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.AD!MTB"
        threat_id = "2147750146"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sample AddIn Project" ascii //weight: 1
        $x_1_2 = "\\SelectCaseEnum.vbp" wide //weight: 1
        $x_1_3 = "uses windows hooks" wide //weight: 1
        $x_1_4 = "Function VirtualAlloc Lib \"kernel32\" (lpAddress As Any, ByVal dwSize" ascii //weight: 1
        $x_1_5 = "NtQueryInformationProcess" wide //weight: 1
        $x_1_6 = "Classic Aeroplane Game" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_AD_2147750146_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.AD!MTB"
        threat_id = "2147750146"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bEAN bEAN bEAN bEAN" ascii //weight: 1
        $x_1_2 = "revegetated2" ascii //weight: 1
        $x_1_3 = "subdolousness" ascii //weight: 1
        $x_1_4 = "nachitoch7" ascii //weight: 1
        $x_1_5 = "staggards3" ascii //weight: 1
        $x_1_6 = "HARTSHORNE" ascii //weight: 1
        $x_1_7 = "Lawhand6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_AE_2147750329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.AE!MTB"
        threat_id = "2147750329"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f 57 c8 81 [0-255] 39 18 75 [0-255] ff d0 [0-255] 8b 1c 17 [0-16] 31 f3 [0-16] 11 1c 10 [0-16] 83 c2 04 [0-16] 81 fa ?? ?? 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_AF_2147750890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.AF!MTB"
        threat_id = "2147750890"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 fb 00 66 81 [0-255] ff d2 [0-255] ff 37 [0-47] 5b [0-47] 31 f3 [0-47] 01 1c 10 [0-47] 83 c2 04 [0-79] 81 fa ?? ?? 00 00 0f 85 ?? ff ff ff [0-79] ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 14 0a f7 c7 [0-255] ff d2 [0-255] ff 37 [0-47] 5b [0-47] 31 f3 [0-63] 8f 04 10 [0-47] 83 c2 04 [0-79] 81 fa ?? ?? 00 00 0f 85 ?? ?? ff ff [0-79] ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_VBKrypt_AG_2147753249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.AG!MTB"
        threat_id = "2147753249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 f1 85 c0 85 ff eb [0-255] 66 ?? ?? ?? ?? 89 0b eb [0-111] 83 c2 04 85 d2 66 ?? ?? ?? ?? eb [0-111] 83 c7 04 66 ?? ?? ?? ?? 81 ff ?? ?? ?? ?? eb [0-111] 81 fa ?? ?? 00 00 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_QO_2147754382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.QO!MTB"
        threat_id = "2147754382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 04 24 00 57 83 c7 01 5f c1 e7 00 c1 ee 00 83 c7 00 83 c7 00 d9 d0 83 04 24 00 33 3c 24 4a 83 c2 01 c1 ee 00 83 c7 00 f8 83 ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_AI_2147754404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.AI!MTB"
        threat_id = "2147754404"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GRDMCg8wZz59Q01YSP784jFL63" wide //weight: 1
        $x_1_2 = "MQXFBX70ou6qdZWbolt1KRmjf185" wide //weight: 1
        $x_1_3 = "Xbey68pa40JBN1l06Mi142" wide //weight: 1
        $x_1_4 = "Tobakshand" ascii //weight: 1
        $x_1_5 = "Earableosc" ascii //weight: 1
        $x_1_6 = "ISOGENOU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_AH_2147754555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.AH!MTB"
        threat_id = "2147754555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 37 81 fa ?? ?? ?? ?? 66 [0-31] 59 [0-31] e8 ?? ?? 00 00 [0-111] 89 0b [0-31] 83 c2 04 [0-31] 83 c7 04 [0-111] e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_AJ_2147754740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.AJ!MTB"
        threat_id = "2147754740"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vMBFzxM8xRsmm9AjFQOTqqOQQuT8G7LnCCGEXi4" wide //weight: 1
        $x_1_2 = "oD5R4Y9Bl1GjuZJsqcgFEfeEjHOpHOXJKK4S6L127" wide //weight: 1
        $x_1_3 = "Concelebrations" ascii //weight: 1
        $x_1_4 = "programafregning" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_AK_2147754820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.AK!MTB"
        threat_id = "2147754820"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 34 0a 0f 6a f3 0f 63 cb 0f 6a d1 0f 6a cd 0f 67 d9 66 0f 6b fc 0f 6b cc 66 0f 68 f9 0f 67 e1 0f 6a d1 66 0f 6a da 66 0f 67 ed 66 0f 68 f4 0f 69 ed 5f}  //weight: 1, accuracy: High
        $x_1_2 = {66 0f 63 d2 81 f7 ?? ?? ?? ?? 0f 6a fe 66 0f 67 eb 0f 6b f7 0f 6b d2 0f 6b c9 0f 68 c2 66 0f 6a d5 0f 63 d1 66 0f 68 ec 66 0f 6a f1 0f 6b f0 0f 6a d8 57 66 0f 67 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_AL_2147754824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.AL!MTB"
        threat_id = "2147754824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Eksternater" ascii //weight: 1
        $x_1_2 = "Superclaim2" ascii //weight: 1
        $x_1_3 = "FILMATELIERER" ascii //weight: 1
        $x_1_4 = "Facesheets" ascii //weight: 1
        $x_1_5 = "stampublikummers" ascii //weight: 1
        $x_1_6 = "SMILEHULLER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_AM_2147755384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.AM!MTB"
        threat_id = "2147755384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DISTANCE" ascii //weight: 1
        $x_1_2 = "Accusatives8" ascii //weight: 1
        $x_1_3 = "demonstranterne" ascii //weight: 1
        $x_1_4 = "HCheXLjTWbbaJd8mdI63" wide //weight: 1
        $x_1_5 = "I0fFCYuL7nOj4UhY7ZEj4tpCEw8" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_AM_2147755384_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.AM!MTB"
        threat_id = "2147755384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "xampp_start" ascii //weight: 3
        $x_3_2 = "Polycystic" ascii //weight: 3
        $x_3_3 = "Goopy" ascii //weight: 3
        $x_3_4 = "Daschagga" ascii //weight: 3
        $x_3_5 = "mintmaster7.dll" ascii //weight: 3
        $x_3_6 = "Colopexotomy" ascii //weight: 3
        $x_3_7 = "VB.Timer" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_AN_2147755631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.AN!MTB"
        threat_id = "2147755631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NSKEFORESTILLINGERNES" ascii //weight: 1
        $x_1_2 = "NEURILEMA" ascii //weight: 1
        $x_1_3 = "RESOLVEDNESS" ascii //weight: 1
        $x_1_4 = "heartblock" wide //weight: 1
        $x_1_5 = "Diskbeskrivelsernes" wide //weight: 1
        $x_1_6 = "Scrophulariaceous4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_AO_2147755634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.AO!MTB"
        threat_id = "2147755634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bevaringsforanstaltnings" ascii //weight: 1
        $x_1_2 = "Algoritmekaldet" ascii //weight: 1
        $x_1_3 = "DOBBELTBILLETTER" ascii //weight: 1
        $x_1_4 = "Hyperintelligence4" wide //weight: 1
        $x_1_5 = "PREDISASTROUSLY" wide //weight: 1
        $x_1_6 = "ASTROPHYSICIST" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_AP_2147755753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.AP!MTB"
        threat_id = "2147755753"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Decisionsmodellen" wide //weight: 1
        $x_1_2 = "STORBRITANNIENS" wide //weight: 1
        $x_1_3 = "BUSTERMINALERNES" wide //weight: 1
        $x_1_4 = "PARKERINGSLYGTER" ascii //weight: 1
        $x_1_5 = "SMAABORGERLIGSTE" ascii //weight: 1
        $x_1_6 = "NONAPPEALINGLY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_AP_2147755753_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.AP!MTB"
        threat_id = "2147755753"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 aa 31 86 11 04 f8 14 18 a4 16 2f 31 9d e4 e6 4b 2a db 81 a4 55 51 41 78 f8 1e e7 19 f9 12 00 6d fa aa 3f bc 31 90 c2 43 4f 73}  //weight: 1, accuracy: High
        $x_1_2 = {46 33 f8 25 f7 05 44 f5 99 fe 21 a1 fb ad 6f 3f c3 53 32 60 a5 99 9e 4d fd 1e 23 36 0a 58 44 13 43 6f 7e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_AR_2147755809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.AR!MTB"
        threat_id = "2147755809"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jDHfA6FxoNocg2vz8HVl2yVURII0tr3B09i3rGs31" wide //weight: 1
        $x_1_2 = "M6C0G3US494fFvSBya7m6od49S10wyVQFm6238" wide //weight: 1
        $x_1_3 = "EwyEfuybiDtBD2nRh5nB4WlkjeJGRXM5jNQ240" wide //weight: 1
        $x_1_4 = "Serviceomraades" ascii //weight: 1
        $x_1_5 = "skiltemalere" ascii //weight: 1
        $x_1_6 = "forecastleman" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_AS_2147755926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.AS!MTB"
        threat_id = "2147755926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {ff 32 66 0f [0-63] 83 c2 04 [0-79] 31 1c 24 [0-79] 8f 04 01 [0-79] 83 c0 04 [0-79] 3d ?? ?? 00 00 0f 85 ?? ff ff ff [0-79] ff e1}  //weight: 6, accuracy: Low
        $x_6_2 = {ff 32 0f 60 [0-63] 83 c2 04 [0-79] 31 1c 24 [0-79] 8f 04 01 [0-79] 83 c0 04 [0-79] 3d ?? ?? 00 00 0f 85 ?? ff ff ff [0-79] ff e1}  //weight: 6, accuracy: Low
        $x_1_3 = "Brndselscellernes" ascii //weight: 1
        $x_1_4 = "Gaffelbidderes" ascii //weight: 1
        $x_1_5 = "DISDIACLASIS" ascii //weight: 1
        $x_1_6 = "vMhXVHefHzdGzMutBAwgNEF6KIZPIzrGRfd3Ou34" wide //weight: 1
        $x_1_7 = "L9IfAMJEhaoxla5wodHOrypEj3N5mXa361" wide //weight: 1
        $x_1_8 = "CWOKrfRNTqZJqVllQe4uzOgihv4yHSfkI8PPG120" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VBKrypt_AT_2147756275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.AT!MTB"
        threat_id = "2147756275"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 0c 24 eb 1f 00 8b 0f eb [0-31] 89 0c 24 eb [0-31] 31 34 24 eb [0-31] 59 eb [0-31] 83 c2 04 eb [0-31] 83 d7 04 eb [0-31] 81 fa ?? ?? 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_AV_2147756420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.AV!MTB"
        threat_id = "2147756420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NONCIRCUMSCRIPTIVE" wide //weight: 1
        $x_1_2 = "DISTOMATIDAE" wide //weight: 1
        $x_1_3 = "EKSKLUDERINGS" wide //weight: 1
        $x_1_4 = "UVILKAARLIGHEDENS" ascii //weight: 1
        $x_1_5 = "LINJETLLERES" ascii //weight: 1
        $x_1_6 = "TILLADELSERNE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_AX_2147756485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.AX!MTB"
        threat_id = "2147756485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {89 0c 24 eb 1f 00 8b 0f eb [0-31] 89 0c 24 eb [0-31] 31 34 24 eb [0-31] 59 eb [0-31] 83 c2 04 eb [0-31] 83 c7 04 eb [0-31] 81 fa ?? ?? 00 00 75}  //weight: 6, accuracy: Low
        $x_1_2 = "DRESSIER" wide //weight: 1
        $x_1_3 = "MINDSTEMAALET" wide //weight: 1
        $x_1_4 = "BESKYTTELSESOMRAADERNES" wide //weight: 1
        $x_1_5 = "Transgressor" wide //weight: 1
        $x_1_6 = "KREDITGIVNINGEN" wide //weight: 1
        $x_1_7 = "CANDOUR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VBKrypt_AZ_2147756979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.AZ!MTB"
        threat_id = "2147756979"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MOMENTANEALL" ascii //weight: 1
        $x_1_2 = "OMSVINGS" ascii //weight: 1
        $x_1_3 = "Nonconfidentiality6" ascii //weight: 1
        $x_1_4 = "SPNDESKRUEN" wide //weight: 1
        $x_1_5 = "SLAGKRAFTIGST" wide //weight: 1
        $x_1_6 = "KENDERES" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_BA_2147758805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.BA!MTB"
        threat_id = "2147758805"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 49 0c 8b 1d ?? ?? ?? ?? 68 ?? ?? ?? ?? 66 0f b6 04 01 66 2b 05 ?? ?? ?? ?? c7 85 ?? ff ff ff ff 00 3b 85 ?? ff ff ff 0f 8f ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 51 0c 88 04 3a 8b 0d ?? ?? ?? ?? b8 01 00 00 00 03 c1 0f 80 ?? ?? ?? ?? a3 ?? ?? ?? ?? e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {50 52 ff d7 50 a1 ?? ?? ?? ?? 50 6a 00 ff 15 ?? ?? ?? ?? 8d 4d c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_BB_2147760449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.BB!MTB"
        threat_id = "2147760449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GASTROCOLOTOMYS" ascii //weight: 1
        $x_1_2 = "Syssitaforvarseletpipi" ascii //weight: 1
        $x_1_3 = "Fraadesfidusmaleriersca1" ascii //weight: 1
        $x_1_4 = "Sacralization" ascii //weight: 1
        $x_1_5 = "Electrosteel5" ascii //weight: 1
        $x_1_6 = "Tekstbehandlingssystemets3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_BC_2147761341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.BC!MTB"
        threat_id = "2147761341"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 8b 1d 30 00 00 00 8b 5b 08 8b 83 00 10 00 00 8b 0b 48 39 08 75 fb}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 ff d0 68 ?? ?? ?? ?? 5a 31 c9 81 c9 ?? ?? ?? ?? 8b 34 0a 89 34 08 81 34 08 ?? ?? ?? ?? 83 c1 fc 7d ee ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_BE_2147762362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.BE!MTB"
        threat_id = "2147762362"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rensekremen" wide //weight: 1
        $x_1_2 = "Fylderisterne3" wide //weight: 1
        $x_1_3 = "OVERMANAGED" wide //weight: 1
        $x_1_4 = "BANTAMK" ascii //weight: 1
        $x_1_5 = "Direktor" ascii //weight: 1
        $x_1_6 = "AARSAGSB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_BE_2147762362_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.BE!MTB"
        threat_id = "2147762362"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AHNLAb, INC" wide //weight: 1
        $x_1_2 = "MAKAyama INTEractive" wide //weight: 1
        $x_1_3 = "ITIBiti INC" wide //weight: 1
        $x_1_4 = "EASY-HIDE-Ip vpn" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_BG_2147764692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.BG!MTB"
        threat_id = "2147764692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 34 0a 39 c2 [0-79] 81 f7 [0-31] 89 3c 08 [0-31] 83 e9 04 7d [0-31] ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 34 0a 39 c1 [0-79] 81 f7 [0-31] 89 3c 08 [0-31] 83 e9 04 7d [0-31] ff d0}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 34 0a 39 c6 [0-79] 81 f7 [0-31] 89 3c 08 [0-31] 83 e9 04 7d [0-31] ff d0}  //weight: 1, accuracy: Low
        $x_1_4 = {ff 34 0a 39 c3 [0-79] 81 f7 [0-31] 89 3c 08 [0-31] 83 e9 04 7d [0-31] ff d0}  //weight: 1, accuracy: Low
        $x_1_5 = {ff 34 0a 39 c7 [0-79] 81 f7 [0-31] 89 3c 08 [0-31] 83 e9 04 7d [0-31] ff d0}  //weight: 1, accuracy: Low
        $x_1_6 = {ff 34 0a 39 d0 [0-79] 81 f7 [0-31] 89 3c 08 [0-31] 83 e9 04 7d [0-31] ff d0}  //weight: 1, accuracy: Low
        $x_1_7 = {39 c6 ff 34 0a [0-79] 81 f7 [0-31] 89 3c 08 [0-31] 83 e9 04 7d [0-31] ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_VBKrypt_BI_2147765647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.BI!MTB"
        threat_id = "2147765647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 34 0a 0f 67 c1 [0-95] 81 f6 ?? ?? ?? ?? 0f 69 e5 [0-255] 89 34 08 0f 63 d8 [0-79] 49 [0-255] 49 [0-255] 49 [0-255] 49 0f 8d ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_BH_2147766626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.BH!MTB"
        threat_id = "2147766626"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e1 00 8b 99 [0-31] 53 [0-31] 81 34 24 [0-31] 8f 04 08 [0-31] 41 [0-47] 83 c1 f8 7d [0-31] ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_BD_2147766775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.BD!MTB"
        threat_id = "2147766775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WinWord.Grabber" ascii //weight: 1
        $x_1_2 = "grabDoc" ascii //weight: 1
        $x_1_3 = "Downexec" wide //weight: 1
        $x_1_4 = "avgnt.exe" wide //weight: 1
        $x_1_5 = "Program Files\\COMODO" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_BJ_2147767154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.BJ!MTB"
        threat_id = "2147767154"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b 43 4f 47 0f 6e 04 0a 4a 42 ?? 0f 6e cb 4f 47 4b 43 0f ef c1 4f 47 4f 47 0f 7e c7 49 41 4f 47 89 3c 08 4e 46 4e 46 83 e9 28 f8 ?? 83 c1 2c 4f 47 4e 46 81 f9 ?? ?? 00 00 75 c5 4f 47 4f 47 ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_BL_2147767248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.BL!MTB"
        threat_id = "2147767248"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SANSEAPPARATERS" wide //weight: 1
        $x_1_2 = "HETEROCHROMOUS" wide //weight: 1
        $x_1_3 = "ADOPTIVMDRES" wide //weight: 1
        $x_1_4 = "OUTSHOVINGL" ascii //weight: 1
        $x_1_5 = "NONCONFORMIS" ascii //weight: 1
        $x_1_6 = "RACEMOCAR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_BK_2147768345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.BK!MTB"
        threat_id = "2147768345"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 1c 0a fc 50 [0-31] c1 fb 00 81 f3 ?? ?? ?? ?? eb [0-79] c1 ca 00 83 f6 00 c1 fb 00 c1 e1 00 89 1c 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_BP_2147771572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.BP!MTB"
        threat_id = "2147771572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Novo_ComCrypt" ascii //weight: 1
        $x_1_2 = "Genoma.vbp" ascii //weight: 1
        $x_1_3 = "@r_Decode" ascii //weight: 1
        $x_1_4 = "JScript" ascii //weight: 1
        $x_1_5 = "href" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_BQ_2147772837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.BQ!MTB"
        threat_id = "2147772837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Junk Programs" ascii //weight: 1
        $x_1_2 = "Debuggy By Vanja Fuckar" ascii //weight: 1
        $x_1_3 = "For Hacking" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_BR_2147772838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.BR!MTB"
        threat_id = "2147772838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\SpreadSheeth.vbp" ascii //weight: 1
        $x_1_2 = "enemy" ascii //weight: 1
        $x_1_3 = "PicGBullet" ascii //weight: 1
        $x_1_4 = "Collision Detection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_BF_2147788058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.BF!MTB"
        threat_id = "2147788058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Zopbox, nc" wide //weight: 1
        $x_1_2 = "Gitoin foect" wide //weight: 1
        $x_1_3 = "Bmith coration" wide //weight: 1
        $x_1_4 = "Clero.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_DS_2147788488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.DS!MTB"
        threat_id = "2147788488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {18 43 00 31 18 43 00 45 18 43 00 68 18 43 00 18 19 43 00 1d 19 43 00 1d 19 43 00 3c 19 43 00 4b 19 43 00 d1 19 43 00 73}  //weight: 2, accuracy: High
        $x_2_2 = {b8 9c 54 b9 32 9f e7 85 02 9a 94 35 f9 47 95 89 7b 04 83 e2 31 ef 2a 4f ad 33 99 66 cf 11 b7}  //weight: 2, accuracy: High
        $x_2_3 = {00 ac 10 34 47 67 3e 32 41 2b 1a 75 bb 2a f1 40 93 81 a1 19 15 6a 00 00 00 4c a4 99 17 89 dc ec bc 3b bd 2d 33 e2}  //weight: 2, accuracy: High
        $x_2_4 = {0d 14 00 00 1e 00 27 2e 35 3c 44 4b 52 59 60 68 6f 00 78 7f 86 8e 95 9c 00 a4 ac}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_VBKrypt_DS_2147788488_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.DS!MTB"
        threat_id = "2147788488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "foricor tbr" wide //weight: 1
        $x_1_2 = "yavae rjtjer" wide //weight: 1
        $x_1_3 = "salAvino vilidilr" wide //weight: 1
        $x_1_4 = "rilAvino dalivilr" wide //weight: 1
        $x_1_5 = "lesedivosic dicr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_AVS_2147794357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.AVS!MTB"
        threat_id = "2147794357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Demarkationslinjens7" ascii //weight: 2
        $x_2_2 = "nervemedicins" ascii //weight: 2
        $x_2_3 = "knopskyde" ascii //weight: 2
        $x_2_4 = "stningsstrukturer" ascii //weight: 2
        $x_2_5 = "Celleslims" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_DA_2147816263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.DA!MTB"
        threat_id = "2147816263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DllRegisterServer" ascii //weight: 3
        $x_3_2 = "CallWindowProcW" ascii //weight: 3
        $x_3_3 = "p05kq4y8Y1YNX" wide //weight: 3
        $x_3_4 = "bgk5p5r2W2P0I4B2xi" wide //weight: 3
        $x_3_5 = "VBRUN" ascii //weight: 3
        $x_3_6 = "Form_Load" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBKrypt_DZ_2147892257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKrypt.DZ!MTB"
        threat_id = "2147892257"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "R95C4CBC2C6A5C6C4BBC0B9A6C194BBC0B3C4CB93" wide //weight: 1
        $x_1_2 = "S8CAAB988B4B2B5B7AAB8B8AAA98BAEB1AA98AEBFAA9C" wide //weight: 1
        $x_1_3 = "UUD.C..N.D.MKZFWQNW.IWOUB.STFTX.VH" wide //weight: 1
        $x_1_4 = "H95B7AF87A8A6B2B0B3B5A8B6B685B8A9A9A8B5" wide //weight: 1
        $x_1_5 = {3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 12 16 f5 ad 9f 46 d3 41 96 86 7b 29 e2}  //weight: 1, accuracy: High
        $x_1_6 = "8gUkcj1nO2EgOXMrbzHyO0JkCHludPYFPXkrZQAFcwNhGWUdbYIP8jVEblpPUvAFC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

