rule Trojan_MSIL_Falock_PRAC_2147932483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Falock.PRAC!MTB"
        threat_id = "2147932483"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Falock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {5d 91 09 1b 58 08 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 9c 09 17 58}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

