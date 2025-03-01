rule Trojan_MSIL_Cryptinject_SE_2147759714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cryptinject.SE!MTB"
        threat_id = "2147759714"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 35 00 00 04 06 7e 35 00 00 04 06 91 7e 36 00 00 04 06 7e 36 00 00 04 8e 69 5d 91 61 d2 9c 1c 0c 2b 90 06 17 58 0a 16 0c 2b 88 06 7e 35 00 00 04 28 76 00 00 06 32 07 1a 0c 38 74 ff ff ff 1d 2b f7 28 95 00 00 0a 7e 40 00 00 04 fe 06 7e 00 00 06 73 96 00 00 0a 6f 97 00 00 0a 2a d0 77 00 00 06 26 2a}  //weight: 1, accuracy: High
        $x_1_2 = {1f 19 8d 06 00 00 01 25 d0 46 00 00 04 28 01 00 00 0a 80 36 00 00 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

