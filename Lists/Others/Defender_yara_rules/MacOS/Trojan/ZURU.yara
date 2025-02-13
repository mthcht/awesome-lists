rule Trojan_MacOS_ZURU_A_2147796183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/ZURU.A"
        threat_id = "2147796183"
        type = "Trojan"
        platform = "MacOS: "
        family = "ZURU"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "===========888888888 code:@%@" ascii //weight: 1
        $x_1_2 = "myOCLog" ascii //weight: 1
        $x_1_3 = "AFNetworking/AFHTTPSessionManager" ascii //weight: 1
        $x_1_4 = "runShellWithCommand:completeBlock" ascii //weight: 1
        $x_1_5 = "/Users/erdou/Desktop/mac" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

