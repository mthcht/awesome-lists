rule TrojanDownloader_Java_OpenConnection_PM_2147655410_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Java/OpenConnection.PM"
        threat_id = "2147655410"
        type = "TrojanDownloader"
        platform = "Java: Java binaries (classes)"
        family = "OpenConnection"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "36"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "java/net/URL" ascii //weight: 5
        $x_5_2 = "java/lang/System" ascii //weight: 5
        $x_5_3 = "java/lang/StringBuilder" ascii //weight: 5
        $x_5_4 = "java/io/ByteArrayOutputStream" ascii //weight: 5
        $x_4_5 = "getClassLoader" ascii //weight: 4
        $x_4_6 = "getRuntime" ascii //weight: 4
        $x_4_7 = "URL.openStream" ascii //weight: 4
        $x_4_8 = "setProperty" ascii //weight: 4
        $x_3_9 = "newInstance" ascii //weight: 3
        $x_3_10 = "useSystemProxies" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 4 of ($x_4_*) and 2 of ($x_3_*))) or
            ((4 of ($x_5_*) and 3 of ($x_4_*) and 2 of ($x_3_*))) or
            ((4 of ($x_5_*) and 4 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Java_OpenConnection_PP_2147656891_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Java/OpenConnection.PP"
        threat_id = "2147656891"
        type = "TrojanDownloader"
        platform = "Java: Java binaries (classes)"
        family = "OpenConnection"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "java/applet/Applet" ascii //weight: 5
        $x_5_2 = "java/io/ByteArrayInputStream" ascii //weight: 5
        $x_5_3 = "java/lang/reflect/Method" ascii //weight: 5
        $x_4_4 = "java/lang/StringBuilder" ascii //weight: 4
        $x_4_5 = "getClassLoader" ascii //weight: 4
        $x_1_6 = {78 2a 1c 04 60 b6 10 b8 60 91 54}  //weight: 1, accuracy: High
        $x_1_7 = {11 36 11 36 15 15 a4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

