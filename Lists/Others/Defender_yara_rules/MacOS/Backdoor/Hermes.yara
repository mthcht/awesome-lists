rule Backdoor_MacOS_Hermes_A_2147921851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Hermes.A!MTB"
        threat_id = "2147921851"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Hermes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Hermes/http.swift" ascii //weight: 1
        $x_1_2 = "Hermes/SwCrypt.swift" ascii //weight: 1
        $x_1_3 = "Hermes/crypto.swift" ascii //weight: 1
        $x_5_4 = {ff 83 01 d1 f8 5f 02 a9 f6 57 03 a9 f4 4f 04 a9 fd 7b 05 a9 fd 43 01 91 15 d8 43 a9 c8 ee 78 d3 a1 be 40 92 df 02 43 f2 29 00 88 9a a9 ?? ?? ?? f3 03 00 aa 96 2b ?? ?? 36 03 ?? ?? b5 2c ?? ?? c8 ee 40 92 00 81 00 91}  //weight: 5, accuracy: Low
        $x_5_5 = {40 33 40 f9 a8 4c 8e d2 48 ee ad f2 48 0e c0 f2 09 a0 fc d2 48 a7 05 a9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MacOS_Hermes_B_2147923942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Hermes.B!MTB"
        threat_id = "2147923942"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Hermes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MYTHIC_POST_RESPONSE" ascii //weight: 1
        $x_1_2 = "downloadIsScreenshot" ascii //weight: 1
        $x_1_3 = "uploadTotalChunks" ascii //weight: 1
        $x_1_4 = "HERMES_POST_RESPONSE" ascii //weight: 1
        $x_1_5 = "screenshotTotalDisplays" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

