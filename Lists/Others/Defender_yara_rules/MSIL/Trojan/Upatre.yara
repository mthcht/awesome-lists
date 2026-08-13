rule Trojan_MSIL_Upatre_SX_2147976094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Upatre.SX!MTB"
        threat_id = "2147976094"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {06 28 07 00 00 0a 0b 28 08 00 00 0a 72 ?? ?? 00 70 6f 09 00 00 0a 0c 07 08 28 02 00 00 06 0d 09 16}  //weight: 20, accuracy: Low
        $x_10_2 = "InjectConfigAccount" ascii //weight: 10
        $x_1_3 = "LoadCredential" ascii //weight: 1
        $x_1_4 = "UpdateLoginUsers" ascii //weight: 1
        $x_1_5 = "NfaLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

