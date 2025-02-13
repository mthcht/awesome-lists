rule Trojan_MSIL_Steam_AMQ_2147788368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Steam.AMQ!MTB"
        threat_id = "2147788368"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Steam"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2d 1b 26 02 06 ?? 2d 18 26 26 06 02 7b ?? 00 00 0a 7b ?? 00 00 0a fe 01 16 fe 01 2b 0a 0a 2b e3 7d ?? 00 00 0a 2b e3 2a}  //weight: 10, accuracy: Low
        $x_3_2 = "ToBase64String" ascii //weight: 3
        $x_3_3 = "FromBase64String" ascii //weight: 3
        $x_3_4 = "CipherMode" ascii //weight: 3
        $x_3_5 = "DebuggerHiddenAttribute" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

