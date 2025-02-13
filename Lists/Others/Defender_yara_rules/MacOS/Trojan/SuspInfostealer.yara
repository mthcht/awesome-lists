rule Trojan_MacOS_SuspInfostealer_X_2147919176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspInfostealer.X"
        threat_id = "2147919176"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspInfostealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "STRATOFEAR" ascii //weight: 6
        $x_1_2 = "/Library/Fonts/AppleSDGothicNeo" ascii //weight: 1
        $x_1_3 = "basic_string/Library/Fonts/pingfang" ascii //weight: 1
        $x_1_4 = "/usr/sbin/system_profiler SPHardwareDataType" ascii //weight: 1
        $x_1_5 = "/usr/bin/sw_vers" ascii //weight: 1
        $x_1_6 = "dscl . -list /Users | grep -v '^_'" ascii //weight: 1
        $x_1_7 = {44 6f 6d 61 69 6e 3a 20 00 4d 6f 6e 69 74 6f 72 69 6e 67 20 44 65 76 69 63 65 20 4d 6f 75 6e 74 73 3a 20 00 2f 56 6f 6c 75 6d 65 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

