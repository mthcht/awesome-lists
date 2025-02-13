rule Trojan_MSIL_CryptMiner_NZK_2147836917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptMiner.NZK!MTB"
        threat_id = "2147836917"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "transfer.sh/get/" wide //weight: 3
        $x_3_2 = "afa8-3a9d4430dcc1" ascii //weight: 3
        $x_3_3 = {55 02 c0 09 00 00 00 00 fa 25 33 00 16 00 00 01}  //weight: 3, accuracy: High
        $x_1_4 = "DecodingBytes" ascii //weight: 1
        $x_1_5 = "Download" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptMiner_MBXT_2147920581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptMiner.MBXT!MTB"
        threat_id = "2147920581"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {57 75 69 50 70 54 4a 78 6c 67 52 71 43 41 48 37 32 6c 00 56 67 30 78 6f 4c 52 33 51 6e 78 35 6f 4f 53 4d 38 65 00 4e 47 70 69}  //weight: 3, accuracy: High
        $x_2_2 = "ScoutVerity_BlueParka.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

