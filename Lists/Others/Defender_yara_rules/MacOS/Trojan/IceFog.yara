rule Trojan_MacOS_IceFog_A_2147745847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/IceFog.A!MTB"
        threat_id = "2147745847"
        type = "Trojan"
        platform = "MacOS: "
        family = "IceFog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/Contents/Resources/.launchd.app" ascii //weight: 5
        $x_1_2 = "/Contents/Resources/Img2icns.app" ascii //weight: 1
        $x_1_3 = "appst0re.net" ascii //weight: 1
        $x_1_4 = "UCHostInf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_IceFog_B_2147755723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/IceFog.B!MTB"
        threat_id = "2147755723"
        type = "Trojan"
        platform = "MacOS: "
        family = "IceFog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/Contents/Resources/.launchd.app" ascii //weight: 1
        $x_1_2 = {25 40 2f 75 70 6c 6f 61 64 2e 61 73 70 78 3f 66 69 6c 65 70 61 74 68 3d 6f 72 64 65 72 26 66 69 6c 65 6e 61 6d 65 3d 25 40 2e 6a 70 67 00 75 70 6c 6f 61 64 00 75 70 6c 6f 61 64 73 00 64 6f 77 6e 6c 6f 61 64}  //weight: 1, accuracy: High
        $x_1_3 = {48 43 48 6f 73 74 49 6e 66 00 48 43 4e 65 74 00 48 43 55 70 44 6f 77 6e 6c 6f 61 64 00 4b 65 79 4c 6f 67 67 65 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

