rule VirTool_Java_Donk_2147661538_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Java/Donk!ldr"
        threat_id = "2147661538"
        type = "VirTool"
        platform = "Java: Java binaries (classes)"
        family = "Donk"
        severity = "Critical"
        info = "ldr: loader component of a malware"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "java/security/cert/Certificate" ascii //weight: 5
        $x_5_2 = "java/security/Permissions" ascii //weight: 5
        $x_5_3 = "java/security/ProtectionDomain" ascii //weight: 5
        $x_5_4 = "java/security/AllPermission" ascii //weight: 5
        $x_4_5 = {73 65 63 75 72 69 74 79 ?? 43 6f 64 65 53 6f 75 72 63 65}  //weight: 4, accuracy: Low
        $x_4_6 = {72 65 66 6c 65 63 74 ?? 43 6f 6e 73 74 72 75 63 74 6f 72}  //weight: 4, accuracy: Low
        $x_1_7 = "net/URL" ascii //weight: 1
        $x_1_8 = "newInstance" ascii //weight: 1
        $x_2_9 = "~spawn" ascii //weight: 2
        $x_10_10 = {12 12 b8 3a 19 b6 57 bb 59 bb 59 b7}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_4_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

