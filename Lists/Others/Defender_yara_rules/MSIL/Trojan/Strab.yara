rule Trojan_MSIL_Strab_AMMD_2147905488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Strab.AMMD!MTB"
        threat_id = "2147905488"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {05 11 0f 8f ?? 00 00 01 25 71 ?? 00 00 01 11 ?? 11 ?? 6f ?? 00 00 0a a5 ?? 00 00 01 61 d2 81}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Strab_ISAA_2147905878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Strab.ISAA!MTB"
        threat_id = "2147905878"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 11 11 8f ?? 00 00 01 25 71 ?? 00 00 01 11 ?? 11 13 7e ?? 00 00 04 28 ?? 01 00 06 a5 ?? 00 00 01 61 d2}  //weight: 5, accuracy: Low
        $x_1_2 = "Angelo" ascii //weight: 1
        $x_1_3 = "Correct" ascii //weight: 1
        $x_1_4 = "RemoteObjects" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

