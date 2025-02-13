rule Trojan_Java_AdwindAC_YA_2147754547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Java/AdwindAC.YA!MTB"
        threat_id = "2147754547"
        type = "Trojan"
        platform = "Java: Java binaries (classes)"
        family = "AdwindAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gtvbcte" ascii //weight: 1
        $x_1_2 = "cbeqgqbgnpmc" ascii //weight: 1
        $x_1_3 = "iizky" ascii //weight: 1
        $x_1_4 = {6e 7d 7f 6b 6a 7d 4e 4a 54 4a 42 6b 65 2a}  //weight: 1, accuracy: High
        $x_1_5 = "}ii\\J" ascii //weight: 1
        $x_1_6 = "SecretKeySpec" ascii //weight: 1
        $x_1_7 = "OK^JK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

