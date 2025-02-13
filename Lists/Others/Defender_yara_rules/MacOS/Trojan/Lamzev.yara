rule Trojan_MacOS_Lamzev_A_2147748684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Lamzev.A!MTB"
        threat_id = "2147748684"
        type = "Trojan"
        platform = "MacOS: "
        family = "Lamzev"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Trojan parameters:" ascii //weight: 1
        $x_1_2 = "HACKING MODE:" ascii //weight: 1
        $x_1_3 = "Bind shell service name:" ascii //weight: 1
        $x_1_4 = "file buffer to small.. how fucking big iz ur Info.plist??" ascii //weight: 1
        $x_1_5 = "LOL I HOPE U BACKED UP UR EXE. U MAY FIND IT IZ.. BONERED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

