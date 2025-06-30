rule Trojan_MSIL_LimeRat_SBR_2147772915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LimeRat.SBR!MSR"
        threat_id = "2147772915"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LimeRat"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://github.com/LimerBoy/StormKitty" ascii //weight: 1
        $x_1_2 = "get_Target" ascii //weight: 1
        $x_1_3 = "DecodeDirectBits" ascii //weight: 1
        $x_1_4 = "get_CurrentDomain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LimeRat_AD_2147945021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LimeRat.AD!MTB"
        threat_id = "2147945021"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LimeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {05 0e 04 7e 0c 00 00 04 20 24 02 00 00 7e 0c 00 00 04 20 24 02 00 00 91 05 5a 20 de 00 00 00 5f 9c 61 1f 6c 59 06 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

