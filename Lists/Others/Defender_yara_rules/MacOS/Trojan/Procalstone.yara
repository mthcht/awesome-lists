rule Trojan_MacOS_Procalstone_C_2147745176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Procalstone.C!MTB"
        threat_id = "2147745176"
        type = "Trojan"
        platform = "MacOS: "
        family = "Procalstone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "calisto/upload.php" ascii //weight: 1
        $x_1_2 = "C34Mac_Internet_Security_X9_Installer11AppDelegate" ascii //weight: 1
        $x_1_3 = "calisto.zip" ascii //weight: 1
        $x_1_4 = "/.calisto/network.dat" ascii //weight: 1
        $x_1_5 = "calisto/listenyee.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

