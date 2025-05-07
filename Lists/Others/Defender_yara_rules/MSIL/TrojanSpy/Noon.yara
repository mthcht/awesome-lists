rule TrojanSpy_MSIL_Noon_MA_2147782764_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.MA!MTB"
        threat_id = "2147782764"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "JU09tVPGc32NW7" ascii //weight: 3
        $x_3_2 = "U4FWLAtMCj" ascii //weight: 3
        $x_3_3 = "YoMQ2ONUqh5PQV" ascii //weight: 3
        $x_3_4 = "Xenelk.Properties" ascii //weight: 3
        $x_3_5 = "Random" ascii //weight: 3
        $x_3_6 = "DebuggerNonUserCodeAttribute" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SK_2147837075_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SK!MTB"
        threat_id = "2147837075"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 06 06 11 06 9a 1f 10 28 e5 00 00 0a 9c 11 06 17 58 13 06 11 06 06 8e 69 fe 04 13 07 11 07 2d de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SL_2147837077_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SL!MTB"
        threat_id = "2147837077"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 06 06 11 06 9a 1f 10 28 75 00 00 0a 9c 11 06 17 58 13 06 11 06 06 8e 69 fe 04 13 07 11 07 2d de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SM_2147837778_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SM!MTB"
        threat_id = "2147837778"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 06 06 11 06 9a 1f 10 28 18 01 00 0a 9c 11 06 17 58 13 06 11 06 06 8e 69 fe 04 13 07 11 07 2d de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SP_2147849588_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SP!MTB"
        threat_id = "2147849588"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 cd 09 00 70 28 ?? ?? ?? 06 1a 2d 03 26 de 06 0a 2b fb}  //weight: 4, accuracy: Low
        $x_1_2 = "fvua8tb4f77gdmfwqxgryjjw7e58638u" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SR_2147851335_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SR!MTB"
        threat_id = "2147851335"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 04 11 05 6f 2a 00 00 0a 13 08 07 11 04 11 05 6f 2a 00 00 0a 13 09 11 09 28 2b 00 00 0a 13 0a 09 08 11 0a d2 9c 11 05 17 58 13 05 11 05 07 6f 2c 00 00 0a 32 c9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SR_2147851335_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SR!MTB"
        threat_id = "2147851335"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 11 04 07 8e 69 5d 07 11 04 07 8e 69 5d 91 08 11 04 1f 16 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 0a 07 11 04 17 58 07 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 11 04 15 58 13 04 11 04 16 fe 04 16 fe 01 13 05 11 05 2d ac}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SU_2147893560_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SU!MTB"
        threat_id = "2147893560"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 07 08 18 5b 02 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a d2 9c 00 08 18 58 0c 08 06 fe 04 0d 09 2d dd}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SV_2147897289_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SV!MTB"
        threat_id = "2147897289"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 11 14 11 04 5d 13 15 11 14 17 58 13 16 07 11 15 91 13 17 07 11 15 11 17 08 11 14 1f 16 5d 91 61 07 11 16 11 04 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 11 14 17 58 13 14 11 14 11 04 09 17 58 5a fe 04 13 18 11 18 2d b2}  //weight: 2, accuracy: High
        $x_2_2 = "ProQuota.Properties.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SW_2147897486_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SW!MTB"
        threat_id = "2147897486"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 09 5d 13 04 06 1f 16 5d 13 0a 06 17 58 09 5d 13 0b 07 11 04 91 11 06 11 0a 91 61 13 0c 20 00 01 00 00 13 05 11 0c 07 11 0b 91 59 11 05 58 11 05 5d 13 0d 07 11 04 11 0d d2 9c 06 17 58 0a 06 09 11 07 17 58 5a fe 04 13 0e 11 0e 2d b2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SX_2147898758_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SX!MTB"
        threat_id = "2147898758"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 07 6f 0d 00 00 0a 03 58 20 00 01 00 00 5d 0c 08 16 2f 08 08 20 00 01 00 00 58 0c 06 07 08 d1 9d 07 17 58 0b 07 02 6f 0c 00 00 0a 32 d2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_ST_2147901750_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.ST!MTB"
        threat_id = "2147901750"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 08 06 08 91 20 a7 20 3a 3a 28 27 00 00 06 28 ?? ?? ?? 0a 59 d2 9c 08 17 58 0c 08 06 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SY_2147902569_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SY!MTB"
        threat_id = "2147902569"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 11 07 20 00 dc 00 00 5d 13 08 08 11 08 91 13 09 11 07 1f 16 5d 13 0a 08 11 08 11 09 1f 16 8d c5 00 00 01 25 d0 5d 00 00 04 28 e1 00 00 0a 11 0a 91 61 08 11 07 17 58 20 00 dc 00 00 5d 91 09 58 09 5d 59 d2 9c 00 11 07 17 58 13 07 11 07 20 00 dc 00 00 fe 04 13 0b 11 0b 2d a4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SZ_2147905069_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SZ!MTB"
        threat_id = "2147905069"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 06 09 6a 5d d4 07 11 06 09 6a 5d d4 91 08 11 06 08 8e 69 6a 5d d4 91 61 28 42 00 00 0a 07 11 06 17 6a 58 09 6a 5d d4 91 28 43 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 44 00 00 0a 9c 00 11 06 17 6a 58 13 06 11 06 09 17 59 6a fe 02 16 fe 01 13 07 11 07 2d a4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SA_2147906162_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SA!MTB"
        threat_id = "2147906162"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 0c 17 58 11 07 5d 91 13 0d 07 11 0c 91 13 0e 08 11 0c 08 6f 44 00 00 0a 5d 6f 45 00 00 0a 13 0f 11 0e 11 0f 61 11 0d 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 10 07 11 0c 11 10 d2 9c 00 11 0c 17 58 13 0c 11 0c 11 07 fe 04 13 11 11 11 2d ad}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SB_2147906164_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SB!MTB"
        threat_id = "2147906164"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 0b 11 0c 91 07 11 07 17 58 11 06 5d 91 13 0d 08 11 07 08 6f 65 00 00 0a 5d 6f 66 00 00 0a 13 0e 11 0e 61 11 0d 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 0f 07 11 07 11 0f d2 9c 11 07 17 58 13 07 11 0c 17 58 13 0c 11 0c 11 0b 8e 69 32 b0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SC_2147906165_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SC!MTB"
        threat_id = "2147906165"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 08 11 07 91 13 09 11 06 17 58 08 5d 13 0a 07 11 06 91 11 09 61 07 11 0a 91 59 20 00 01 00 00 58 13 0b 07 11 06 11 0b 20 ff 00 00 00 5f d2 9c 11 06 17 58 13 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SC_2147906165_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SC!MTB"
        threat_id = "2147906165"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 06 11 07 91 07 11 04 17 58 09 5d 91 13 08 08 11 04 1f 16 5d 91 13 09 11 09 61 11 08 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 0a 07 11 04 11 0a d2 9c 11 04 17 58 13 04 11 07 17 58 13 07 11 07 11 06 8e 69 32 b9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_ARA_2147910756_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.ARA!MTB"
        threat_id = "2147910756"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 07 11 10 07 11 10 91 17 8d ?? ?? ?? 01 25 16 20 c6 00 00 00 9c 11 10 17 5d 91 61 d2 9c 00 11 10 17 58 13 10 11 10 07 8e 69 fe 04 13 11 11 11 2d ce}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SH_2147917679_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SH!MTB"
        threat_id = "2147917679"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 07 61 13 1a 07 09 17 58 08 5d 91 13 1b 11 1a 11 1b 59}  //weight: 2, accuracy: High
        $x_2_2 = "heidi_schwartz_C968.Properties.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SJ_2147917687_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SJ!MTB"
        threat_id = "2147917687"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 09 11 07 09 8e 69 5d 91 13 08 07 11 07 91 11 08 61 13 09 11 07 17 58 08 5d 13 0a 07}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SAK_2147917841_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SAK!MTB"
        threat_id = "2147917841"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {04 05 5d 05 58 05 5d 0a 03 06 91 0b 07 0e 04 61 0c 08 0e 05 59 20 00 02 00 00 58 0d 2b 00 09 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SBK_2147918591_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SBK!MTB"
        threat_id = "2147918591"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 05 08 5d 08 58 08 5d 13 09 07 11 09 91 11 06 61 11 08 59}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SCK_2147920469_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SCK!MTB"
        threat_id = "2147920469"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 1d 5d 16 fe 01 0d 09 2c 0b 06 08 06 08 91 1f 4b 61 b4 9c 00 00 08 17 d6 0c 08 07 31 e2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SCK_2147920469_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SCK!MTB"
        threat_id = "2147920469"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 06 17 d6 13 06 11 06 06 6f 3b 00 00 0a fe 04 13 08 11 08 2d 9e}  //weight: 2, accuracy: High
        $x_2_2 = "ComboBoxBind.MainForm.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SDK_2147921709_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SDK!MTB"
        threat_id = "2147921709"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 07 11 0a 95 11 07 11 09 95 58 20 ff 00 00 00 5f 13 10 11 06 11 08 11 04 11 08 91 11 07 11 10 95 61 28 48 00 00 0a 9c 11 08 17 58 13 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SEK_2147923798_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SEK!MTB"
        threat_id = "2147923798"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "skwas.Forms.Properties.Resources" ascii //weight: 2
        $x_2_2 = "df406eab-8be0-4764-b4f8-28512fc19489" ascii //weight: 2
        $x_2_3 = "2007-2009 skwas" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SFK_2147925058_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SFK!MTB"
        threat_id = "2147925058"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 11 0a 07 11 0a 91 11 04 11 0b 95 61 d2 9c 00 11 0a 17 58 13 0a 11 0a 07 8e 69 fe 04 13 0e 11 0e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SHK_2147927665_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SHK!MTB"
        threat_id = "2147927665"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 11 04 11 0a 11 04 11 0a 91 20 9d 07 00 00 59 d2 9c 00 11 0a 17 58 13 0a 11 0a 11 04 8e 69 fe 04 13 0b 11 0b 2d d9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SIK_2147930141_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SIK!MTB"
        threat_id = "2147930141"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 06 07 1f 10 5d 04 07 5a 68 9d 02 03 04 07 05 28 44 00 00 06 00 00 07 17 58 0b 07 02 6f b5 00 00 0a 2f 0b 03 6f b1 00 00 0a 05 fe 04 2b 01 16 0c 08 2d cc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SMK_2147934254_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SMK!MTB"
        threat_id = "2147934254"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 19 28 4e 00 00 06 0a 04 07 08 91 6f a1 00 00 0a 00 00 08 17 58 0c 08 03 fe 04 0d 09 2d e0}  //weight: 2, accuracy: High
        $x_2_2 = "WindowsFormsOCR.Properties.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SJK_2147936253_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SJK!MTB"
        threat_id = "2147936253"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 06 91 04 28 16 00 00 06 06 17 58 0a 06 03 32 ef}  //weight: 2, accuracy: High
        $x_2_2 = "TemperatureConverter.Properties.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SKK_2147936254_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SKK!MTB"
        threat_id = "2147936254"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 08 91 07 28 24 00 00 06 2c 0c 06 08 8f 44 00 00 01 28 25 00 00 06 04 06 08 91 6f 38 00 00 0a 08 17 58 0c 08 03 32 d8}  //weight: 2, accuracy: High
        $x_2_2 = "Gma.UserActivityMonitorDemo.Properties.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SLK_2147936256_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SLK!MTB"
        threat_id = "2147936256"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 08 6f 4b 00 00 0a 26 04 07 08 91 6f 4c 00 00 0a 08 17 58 0c 08 03 32 e7}  //weight: 2, accuracy: High
        $x_2_2 = "Sakk Alkalmaz" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SOK_2147939553_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SOK!MTB"
        threat_id = "2147939553"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 09 11 0b 18 5d 16 fe 01 11 0b 19 5d 16 fe 01 60 2d 03 17 2b 01 16 6a d6 13 09 11 0b 17 d6 13 0b 11 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SPK_2147939556_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SPK!MTB"
        threat_id = "2147939556"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 17 58 0b 00 07 02 7b a8 01 00 04 2f 06 07 19 fe 04 2b 01 16 0c 08 2d d2}  //weight: 2, accuracy: High
        $x_2_2 = "QLBH.Properties.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SQK_2147940890_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SQK!MTB"
        threat_id = "2147940890"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 03 11 06 11 0e 91 6f d5 00 00 0a 00 00 11 0e 17 58 13 0e 11 0e 11 07 fe 04 13 0f 11 0f 2d e0}  //weight: 2, accuracy: High
        $x_2_2 = "GMS.Properties.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

