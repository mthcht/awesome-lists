rule Trojan_Java_SDrop_A_2147756704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Java/SDrop.A!MTB"
        threat_id = "2147756704"
        type = "Trojan"
        platform = "Java: Java binaries (classes)"
        family = "SDrop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "invoicesecure.net" ascii //weight: 1
        $x_1_2 = "/footer.jpg" ascii //weight: 1
        $x_1_3 = "C:\\ProgramData\\drvr32.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Java_SDrop_A_2147756704_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Java/SDrop.A!MTB"
        threat_id = "2147756704"
        type = "Trojan"
        platform = "Java: Java binaries (classes)"
        family = "SDrop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Mvoqmqrtpjb.java" ascii //weight: 1
        $x_1_2 = "resources/gbpazxtdxc" ascii //weight: 1
        $x_1_3 = "aoxcdnrrcl.vbs" ascii //weight: 1
        $x_1_4 = {52 75 6e 74 69 6d 65 [0-5] 65 78 65 63}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

