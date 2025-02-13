rule Backdoor_MacOS_Muxler_A_2147746256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Muxler.A!MTB"
        threat_id = "2147746256"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Muxler"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mac src/mac trojan /zlib/" ascii //weight: 1
        $x_1_2 = "/library/LaunchAgents/checkvir.plist" ascii //weight: 1
        $x_1_3 = "bostanlik.com/cgi-mac/wmcheckdir.cgi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

