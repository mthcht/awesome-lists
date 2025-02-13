rule Trojan_MSIL_Lorenz_AMZ_2147840142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lorenz.AMZ!MTB"
        threat_id = "2147840142"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lorenz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0c 01 00 fe 0c 00 00 fe 0c 01 00 fe 0c 00 00 93 fe 09 00 00 7b 14 00 00 04 fe 09 02 00 20 35 f3 78 38 20 61 00 48 ea 61 20 72 8b 58 dd 61 20 35 78 68 0f 59 65 5f 91 fe 09 02 00 60 61 d1 9d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

