rule Trojan_Java_Locker_A_2147751499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Java/Locker.A!MTB"
        threat_id = "2147751499"
        type = "Trojan"
        platform = "Java: Java binaries (classes)"
        family = "Locker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "readmeonnotepad.javaencrypt" ascii //weight: 1
        $x_1_2 = "adress:BAW4VM2dhxYgXeQepOHKHSQVG6NgaEb94" ascii //weight: 1
        $x_1_3 = "You need to send 300$ of bitcoins" ascii //weight: 1
        $x_1_4 = ".javalocker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

