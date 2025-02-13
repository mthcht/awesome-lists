rule TrojanSpy_MacOS_Keylogger_B_2147894236_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MacOS/Keylogger.B!MTB"
        threat_id = "2147894236"
        type = "TrojanSpy"
        platform = "MacOS: "
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SwiftSpy" ascii //weight: 1
        $x_1_2 = "ClipboardMonitor" ascii //weight: 1
        $x_1_3 = "-allkeys" ascii //weight: 1
        $x_1_4 = "/main.swift" ascii //weight: 1
        $x_1_5 = "-keylog" ascii //weight: 1
        $x_1_6 = "-screenshot /tmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

