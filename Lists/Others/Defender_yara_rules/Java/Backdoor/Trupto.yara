rule Backdoor_Java_Trupto_A_2147760835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Java/Trupto.A!MTB"
        threat_id = "2147760835"
        type = "Backdoor"
        platform = "Java: Java binaries (classes)"
        family = "Trupto"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "crossrat/client" ascii //weight: 1
        $x_1_2 = "mediamgrs.jar" ascii //weight: 1
        $x_1_3 = "org/a/a/a/b" ascii //weight: 1
        $x_1_4 = "os.name" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

