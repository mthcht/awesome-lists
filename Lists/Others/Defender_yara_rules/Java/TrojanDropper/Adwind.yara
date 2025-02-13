rule TrojanDropper_Java_Adwind_BD_2147762084_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Java/Adwind.BD!MTB"
        threat_id = "2147762084"
        type = "TrojanDropper"
        platform = "Java: Java binaries (classes)"
        family = "Adwind"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bhmvpxbdye/Mcvzgduwzvz" ascii //weight: 1
        $x_1_2 = "resources/mnvntgseku" ascii //weight: 1
        $x_1_3 = "zmzukrbhek.js" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Java_Adwind_BD_2147762084_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Java/Adwind.BD!MTB"
        threat_id = "2147762084"
        type = "TrojanDropper"
        platform = "Java: Java binaries (classes)"
        family = "Adwind"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mitbadkwad/Moqzhblqwmx" ascii //weight: 1
        $x_1_2 = "lwhunjgfdx.js" ascii //weight: 1
        $x_1_3 = "resources/cztdszdezx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Java_Adwind_BE_2147762667_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Java/Adwind.BE!MTB"
        threat_id = "2147762667"
        type = "TrojanDropper"
        platform = "Java: Java binaries (classes)"
        family = "Adwind"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "idefrtlrib/Mdcpcgeoasb" ascii //weight: 1
        $x_1_2 = "mmveqikmup.js" ascii //weight: 1
        $x_1_3 = "resources/zkqyysxvvr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Java_Adwind_BF_2147763293_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Java/Adwind.BF!MTB"
        threat_id = "2147763293"
        type = "TrojanDropper"
        platform = "Java: Java binaries (classes)"
        family = "Adwind"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "eqphoardle/Mhtuorjsbvx" ascii //weight: 1
        $x_1_2 = "rilesigavf.js" ascii //weight: 1
        $x_1_3 = "resources/ptpznjlndr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

