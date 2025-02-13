rule Trojan_MSIL_Dorifel_ADF_2147847996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dorifel.ADF!MTB"
        threat_id = "2147847996"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dorifel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0b 16 0c 2b 1e 06 08 93 0d 09 19 59 0d 07 09 d1 13 04 12 04 28 2a 00 00 0a 28 16 00 00 0a 0b 08 17 58 0c 08 06 8e 69 32 dc}  //weight: 2, accuracy: High
        $x_1_2 = "VeSiJxjxSoS" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dorifel_SP_2147892567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dorifel.SP!MTB"
        threat_id = "2147892567"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dorifel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 8e b7 18 da 16 da 17 d6 6b 28 3b 00 00 0a 5a 28 3c 00 00 0a 22 00 00 80 3f 58 6b 6c 28 3d 00 00 0a b7 13 04 08 06 11 04 93 6f 3e 00 00 0a 26 09 17 d6 0d 09 11 05 31 c2}  //weight: 2, accuracy: High
        $x_1_2 = "tmp9482.tmp.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dorifel_AA_2147896080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dorifel.AA!MTB"
        threat_id = "2147896080"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dorifel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {fa 25 33 00 16 00 00 02 00 00 00 2c 00 00 00 16 00 00 00 58 00 00 00 a8 00 00 00 49 00 00 00 0b 00 00 00 01 00 00 00 03}  //weight: 10, accuracy: High
        $x_3_2 = "SuppressIldasmAttribute" ascii //weight: 3
        $x_3_3 = "GetExecutingAssembly" ascii //weight: 3
        $x_3_4 = "IsLogging" ascii //weight: 3
        $x_3_5 = "System.Runtime.InteropServices" ascii //weight: 3
        $x_3_6 = "get_IsAlive" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dorifel_EM_2147927564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dorifel.EM!MTB"
        threat_id = "2147927564"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dorifel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DN481C54A864F7ECBE" ascii //weight: 1
        $x_1_2 = "ZYDNGuard" ascii //weight: 1
        $x_1_3 = "RunHVM" ascii //weight: 1
        $x_1_4 = "Startup" ascii //weight: 1
        $x_1_5 = "chromeNotEncode_ProcessedByFody" ascii //weight: 1
        $x_1_6 = "BOSSFlyAway" ascii //weight: 1
        $x_1_7 = "CheckIsInsideTeamDungeonDay" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

