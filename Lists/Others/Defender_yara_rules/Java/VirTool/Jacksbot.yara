rule VirTool_Java_Jacksbot_A_2147667458_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Java/Jacksbot.A!bnd"
        threat_id = "2147667458"
        type = "VirTool"
        platform = "Java: Java binaries (classes)"
        family = "Jacksbot"
        severity = "Critical"
        info = "bnd: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "java/io/FileOutputStream" ascii //weight: 5
        $x_5_2 = "java/io/InputStream" ascii //weight: 5
        $x_5_3 = "java/lang/String" ascii //weight: 5
        $x_5_4 = "java/lang/System" ascii //weight: 5
        $x_2_5 = "getResourceAsStream" ascii //weight: 2
        $x_2_6 = "getRuntime" ascii //weight: 2
        $x_2_7 = "getAbsolutePath" ascii //weight: 2
        $x_2_8 = "createTempFile" ascii //weight: 2
        $x_2_9 = "javax/crypto/spec/SecretKeySpec" ascii //weight: 2
        $x_2_10 = "java/security/spec/AlgorithmParameterSpec" ascii //weight: 2
        $x_2_11 = "java/net/URL" ascii //weight: 2
        $x_2_12 = "java/security/CodeSource" ascii //weight: 2
        $x_2_13 = "java/security/ProtectionDomain" ascii //weight: 2
        $x_2_14 = "java/io/BufferedWriter" ascii //weight: 2
        $x_5_15 = {10 32 b6 19 bb 59 b2 10 32 b7 19 b6 b6}  //weight: 5, accuracy: High
        $x_5_16 = {12 b7 19 b6 b6 12 b6 12 b6 19 b6 12 b6 b6 b6}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_5_*) and 10 of ($x_2_*))) or
            ((6 of ($x_5_*) and 8 of ($x_2_*))) or
            (all of ($x*))
        )
}

