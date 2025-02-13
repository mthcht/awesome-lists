rule Trojan_Java_GBinHost_A_2147667657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Java/GBinHost.A!ldr"
        threat_id = "2147667657"
        type = "Trojan"
        platform = "Java: Java binaries (classes)"
        family = "GBinHost"
        severity = "Critical"
        info = "ldr: loader component of a malware"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "java/net/URLConnection" ascii //weight: 2
        $x_2_2 = "java/util/Enumeration" ascii //weight: 2
        $x_2_3 = "java/util/zip/ZipEntry" ascii //weight: 2
        $x_2_4 = "java/io/BufferedOutputStream" ascii //weight: 2
        $x_2_5 = "java/lang/Runtime" ascii //weight: 2
        $x_2_6 = "getResourceAsStream" ascii //weight: 2
        $x_2_7 = "host" ascii //weight: 2
        $x_2_8 = "sys_name" ascii //weight: 2
        $x_2_9 = "host_name" ascii //weight: 2
        $x_10_10 = {2a b4 b6 b6 2a b4 b8}  //weight: 10, accuracy: High
        $x_10_11 = {2a 59 b4 bb 5a 5f b8 b7 2a b4 b6 b6 b5}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 9 of ($x_2_*))) or
            ((2 of ($x_10_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

