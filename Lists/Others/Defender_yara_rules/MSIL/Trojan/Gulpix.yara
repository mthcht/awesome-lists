rule Trojan_MSIL_Gulpix_CXFF_2147851907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Gulpix.CXFF!MTB"
        threat_id = "2147851907"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gulpix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 29 04 00 00 e9 bc 00 00 00 8a 11 33 c0 84 d2 74 19 56 c1 c8 0d 0f be f2 80}  //weight: 1, accuracy: High
        $x_1_2 = {fa 61 7c 03 83 c6 e0 03 c6 41 8a 11 84 d2 75 e9 5e c3 83}  //weight: 1, accuracy: High
        $x_1_3 = {ec 10 64 a1 30 00 00 00 53 55 56 8b 40 0c 57 89 4c 24 14 8b 40 14 8b f8 89 44 24 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

