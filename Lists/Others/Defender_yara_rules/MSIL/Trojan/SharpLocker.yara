rule Trojan_MSIL_SharpLocker_MIL_2147751580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SharpLocker.MIL!MTB"
        threat_id = "2147751580"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SharpLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 21 00 00 06 25 02 7d ?? ?? ?? ?? 25 11 ?? 11 ?? 9a ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 ?? 17 58 13 ?? 11 ?? 11 ?? 8e 69 32 c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

