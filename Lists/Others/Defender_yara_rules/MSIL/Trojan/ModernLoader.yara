rule Trojan_MSIL_ModernLoader_A_2147851338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ModernLoader.A!MTB"
        threat_id = "2147851338"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ModernLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 d5 a2 fd 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 3a 00 00 00 10 00 00 00 30 00 00 00 54}  //weight: 2, accuracy: High
        $x_1_2 = "set_WindowStyle" ascii //weight: 1
        $x_1_3 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

