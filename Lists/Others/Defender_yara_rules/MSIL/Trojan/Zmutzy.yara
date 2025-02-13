rule Trojan_MSIL_Zmutzy_NT_2147820414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zmutzy.NT!MTB"
        threat_id = "2147820414"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zmutzy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 b7 a2 3f 09 0f 00 00 00 00 00 00 00 00 00 00 02}  //weight: 1, accuracy: High
        $x_1_2 = "2005 Pontiac Sunfire" ascii //weight: 1
        $x_1_3 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii //weight: 1
        $x_1_4 = "Withomy1967.Properties.R" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "RijndaelManaged" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zmutzy_NX_2147829496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zmutzy.NX!MTB"
        threat_id = "2147829496"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zmutzy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TwoLevelEnumerator.Tucson" ascii //weight: 1
        $x_1_2 = "Aquamine" ascii //weight: 1
        $x_1_3 = "GA50BW5F4QHQ54P857" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
        $x_1_5 = "MD5CryptoServiceProvider" ascii //weight: 1
        $x_1_6 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zmutzy_GPD_2147905963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zmutzy.GPD!MTB"
        threat_id = "2147905963"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zmutzy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 17 58 11 [0-48] 59 20 00 01 00 00 58 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

