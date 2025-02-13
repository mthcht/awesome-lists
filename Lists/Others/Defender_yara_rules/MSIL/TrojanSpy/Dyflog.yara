rule TrojanSpy_MSIL_Dyflog_A_2147628814_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Dyflog.A"
        threat_id = "2147628814"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dyflog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "57"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Microsoft.VisualBasic" ascii //weight: 10
        $x_10_2 = "GetAsyncKeyState" ascii //weight: 10
        $x_10_3 = "SmtpClient" ascii //weight: 10
        $x_10_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 10
        $x_10_5 = "Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\" wide //weight: 10
        $x_5_6 = "FloydLogs@gmail.com" wide //weight: 5
        $x_1_7 = "smtp.gmail.com" wide //weight: 1
        $x_1_8 = "Operating System Name :" wide //weight: 1
        $x_1_9 = "Fresh - [LOGS]" wide //weight: 1
        $x_1_10 = "Computer Name :" wide //weight: 1
        $x_1_11 = "User Name :" wide //weight: 1
        $x_1_12 = "[Tab]" wide //weight: 1
        $x_1_13 = "[Ctrl]" wide //weight: 1
        $x_1_14 = "[Alt]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 7 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_MSIL_Dyflog_B_2147646540_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Dyflog.B"
        threat_id = "2147646540"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dyflog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "37"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "GetAsyncKeyState" ascii //weight: 10
        $x_10_2 = "SmtpClient" ascii //weight: 10
        $x_10_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 10
        $x_2_4 = "wadebradleyy@aol.com" wide //weight: 2
        $x_2_5 = "invoice.txt" wide //weight: 2
        $x_1_6 = "{304CE942-6E39-40D8-943A-B913C40C9CD4}" ascii //weight: 1
        $x_1_7 = "HNetCfg.FwAuthorizedApplication" ascii //weight: 1
        $x_1_8 = "[rshi]" wide //weight: 1
        $x_1_9 = "[Ctrl]" wide //weight: 1
        $x_1_10 = "[Alt]" wide //weight: 1
        $x_1_11 = "\\Mozilla\\Firefox\\Profiles" wide //weight: 1
        $x_1_12 = "Microsoft-updates.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

