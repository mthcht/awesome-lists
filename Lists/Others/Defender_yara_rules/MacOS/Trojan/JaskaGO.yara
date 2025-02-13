rule Trojan_MacOS_JaskaGO_A_2147901530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/JaskaGO.A!MTB"
        threat_id = "2147901530"
        type = "Trojan"
        platform = "MacOS: "
        family = "JaskaGO"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "*stealer.Browser" ascii //weight: 1
        $x_1_2 = "BrowserExists" ascii //weight: 1
        $x_1_3 = "GetChromiumProfileData" ascii //weight: 1
        $x_1_4 = "/gary-macos-stealer-malware/agent/stealer" ascii //weight: 1
        $x_1_5 = "getWalletData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

