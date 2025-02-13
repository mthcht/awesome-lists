rule Trojan_MSIL_Glupteba_MBID_2147889024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Glupteba.MBID!MTB"
        threat_id = "2147889024"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {17 fe 01 13 04 11 04 2c 08 06 17 64 02 61 0a 2b 04 06 17 64 0a 00 09 17 59}  //weight: 1, accuracy: High
        $x_1_2 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 00 15 45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 00 11 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 00 1b 44 00 65 00 63 00 6c 00 61 00 72 00 69 00 6e 00 67 00 54 00 79 00 70 00 65 00 00 09 4c 00 6f 00 61 00 64}  //weight: 1, accuracy: High
        $x_1_3 = "4f34-af18-dcba3d14f7d2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

