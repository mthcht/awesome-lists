rule Worm_Java_Inqtana_D_2147745726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Java/Inqtana.D!MTB"
        threat_id = "2147745726"
        type = "Worm"
        platform = "Java: Java binaries (classes)"
        family = "Inqtana"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "applec0re.tgz" ascii //weight: 1
        $x_1_2 = "pwned.dylib" ascii //weight: 1
        $x_1_3 = "InqTest.java" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Java_Inqtana_C_2147745733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Java/Inqtana.C!MTB"
        threat_id = "2147745733"
        type = "Worm"
        platform = "Java: Java binaries (classes)"
        family = "Inqtana"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "w0rms.love.apples.tgz" ascii //weight: 1
        $x_1_2 = "/Library/InputManagers/InqTanaHandler/InqTanaHandler.bundle" ascii //weight: 1
        $x_1_3 = "/Contents/MacOS/InqTanaHandler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

