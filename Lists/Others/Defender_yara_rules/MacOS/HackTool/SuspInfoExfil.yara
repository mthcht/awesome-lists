rule HackTool_MacOS_SuspInfoExfil_E_2147971211_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspInfoExfil.E"
        threat_id = "2147971211"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspInfoExfil"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "api.telegram.org/bot" wide //weight: 4
        $x_4_2 = "/sendMessage" wide //weight: 4
        $x_4_3 = "curl" wide //weight: 4
        $x_1_4 = "osascript -e" wide //weight: 1
        $x_1_5 = "system info" wide //weight: 1
        $x_1_6 = "--data" wide //weight: 1
        $x_1_7 = "chat_id=" wide //weight: 1
        $x_1_8 = "password=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

