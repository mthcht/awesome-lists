rule Trojan_MSIL_CryptSteam_MBXT_2147920582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptSteam.MBXT!MTB"
        threat_id = "2147920582"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptSteam"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {20 ea e0 00 00 28 66 7f 00 06 13 12 20 0b 00 00 00 38 7a 01 00 00 1f 35 13 43 20 22 00 00 00 17}  //weight: 3, accuracy: High
        $x_2_2 = "ViDeoAutoR.Resources.resource" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

