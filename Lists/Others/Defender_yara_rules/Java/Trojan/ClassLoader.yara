rule Trojan_Java_ClassLoader_SA_2147977538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Java/ClassLoader.SA!MTB"
        threat_id = "2147977538"
        type = "Trojan"
        platform = "Java: Java binaries (classes)"
        family = "ClassLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nonvocational/CharringodeumLimbless" ascii //weight: 1
        $x_1_2 = "java/nio/channels/FileLock" ascii //weight: 1
        $x_1_3 = "java/nio/channels/FileChannel" ascii //weight: 1
        $x_1_4 = "addShutdownHook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

