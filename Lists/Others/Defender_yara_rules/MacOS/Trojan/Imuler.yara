rule Trojan_MacOS_Imuler_A_2147745990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Imuler.A!MTB"
        threat_id = "2147745990"
        type = "Trojan"
        platform = "MacOS: "
        family = "Imuler"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/library/LaunchAgents/checkvir.plist" ascii //weight: 1
        $x_1_2 = "/tmp/launch-0rp.dat" ascii //weight: 1
        $x_1_3 = "/cgi-mac/2wmupload.cgi" ascii //weight: 1
        $x_1_4 = "/tmp/CurlUpload -f /tmp/xntaskz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

