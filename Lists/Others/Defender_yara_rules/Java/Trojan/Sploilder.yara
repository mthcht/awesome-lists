rule Trojan_Java_Sploilder_A_2147659889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Java/Sploilder.A"
        threat_id = "2147659889"
        type = "Trojan"
        platform = "Java: Java binaries (classes)"
        family = "Sploilder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "getResourceAsStream" ascii //weight: 2
        $x_2_2 = "createTempFile" ascii //weight: 2
        $x_2_3 = "getRuntime" ascii //weight: 2
        $x_2_4 = "getAbsolutePath" ascii //weight: 2
        $x_2_5 = "setExecutable" ascii //weight: 2
        $x_2_6 = "getCanonicalPath" ascii //weight: 2
        $x_1_7 = "os.name" ascii //weight: 1
        $x_1_8 = "isWindows" ascii //weight: 1
        $x_1_9 = "isMac" ascii //weight: 1
        $x_10_10 = "~spawn" ascii //weight: 10
        $x_10_11 = {19 b6 4d 12 12 b8 3a 19 b6 57 bb}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

