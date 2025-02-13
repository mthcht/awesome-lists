rule Trojan_Java_CrimoApplet_A_2147679808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Java/CrimoApplet.A"
        threat_id = "2147679808"
        type = "Trojan"
        platform = "Java: Java binaries (classes)"
        family = "CrimoApplet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "java/net/URL" ascii //weight: 1
        $x_1_2 = "java/util/logging/Logger" ascii //weight: 1
        $x_1_3 = "java/applet/AppletContext" ascii //weight: 1
        $x_1_4 = "java/io/IOException" ascii //weight: 1
        $x_1_5 = "java/beans/Expression" ascii //weight: 1
        $x_1_6 = "getLogger" ascii //weight: 1
        $x_1_7 = "showDocument" ascii //weight: 1
        $x_5_8 = {b8 9a 2a b6 bb 59 [0-18] b7 3a 2a b6 19 b9}  //weight: 5, accuracy: Low
        $x_5_9 = {12 b6 b6 12 b6 b6 4d}  //weight: 5, accuracy: High
        $x_1_10 = "JSM_onLoadFail" ascii //weight: 1
        $x_1_11 = {53 52 45 53 55 4c 4c 41 [0-5] 45 4c 49 46 4f 52 50}  //weight: 1, accuracy: Low
        $x_5_12 = "AdaoLno_MSJ" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 8 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

