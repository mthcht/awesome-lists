rule Trojan_Java_EvilRat_A_2147755891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Java/EvilRat.A!MTB"
        threat_id = "2147755891"
        type = "Trojan"
        platform = "Java: Java binaries (classes)"
        family = "EvilRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/evilcodez/evilrat/client/BrowserStealer" ascii //weight: 1
        $x_1_2 = {2f 52 6f 61 6d 69 6e 67 [0-34] 55 73 65 72 20 44 61 74 61 2f 44 65 66 61 75 6c 74 2f 4c 6f 67 69 6e 20 44 61 74 61}  //weight: 1, accuracy: Low
        $x_1_3 = "stealAll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

