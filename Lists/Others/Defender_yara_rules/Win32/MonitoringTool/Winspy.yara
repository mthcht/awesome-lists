rule MonitoringTool_Win32_Winspy_14230_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Winspy"
        threat_id = "14230"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Winspy"
        severity = "11"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "\\Desktop\\v58\\Win" wide //weight: 4
        $x_1_2 = "Stealth" ascii //weight: 1
        $x_1_3 = "GetMSNChat" ascii //weight: 1
        $x_1_4 = "GetYahooChat" ascii //weight: 1
        $x_1_5 = "GetAIMChat" ascii //weight: 1
        $x_1_6 = "GetICQChat" ascii //weight: 1
        $x_1_7 = "GetSkypeChat" ascii //weight: 1
        $x_1_8 = "Log file location:" ascii //weight: 1
        $x_1_9 = "Chat Logger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_Winspy_14230_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Winspy"
        threat_id = "14230"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Winspy"
        severity = "11"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "\\Desktop\\v58\\Win" wide //weight: 4
        $x_1_2 = "TimerScreenCapture" ascii //weight: 1
        $x_4_3 = "Win-Spy Shareware." wide //weight: 4
        $x_1_4 = ":*:Enabled:Outlook.exe" wide //weight: 1
        $x_2_5 = "Icon will not appear on Retail version" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_Winspy_14230_2
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Winspy"
        threat_id = "14230"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Winspy"
        severity = "11"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Win-Spy Software" ascii //weight: 5
        $x_5_2 = "Win-Spy Login and Password" ascii //weight: 5
        $x_5_3 = "www.win-spy.com" ascii //weight: 5
        $x_3_4 = "BC COMPUTING" ascii //weight: 3
        $x_2_5 = "Keylog" ascii //weight: 2
        $x_2_6 = "KeyState" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_Winspy_14230_3
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Winspy"
        threat_id = "14230"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Winspy"
        severity = "11"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "{NumLock}" wide //weight: 2
        $x_2_2 = "txtStroke" ascii //weight: 2
        $x_2_3 = "StopKeylog" ascii //weight: 2
        $x_1_4 = "GetAsyncKeyState" ascii //weight: 1
        $x_2_5 = "txtKeyN" ascii //weight: 2
        $x_2_6 = "Date File Created: " wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Winspy_14230_4
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Winspy"
        threat_id = "14230"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Winspy"
        severity = "11"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "\\Desktop\\v58\\Win" wide //weight: 4
        $x_2_2 = "View Attached Log File" wide //weight: 2
        $x_2_3 = "69.46.18.49" wide //weight: 2
        $x_2_4 = "KeyLog" ascii //weight: 2
        $x_2_5 = "win-spy" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_Winspy_14230_5
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Winspy"
        threat_id = "14230"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Winspy"
        severity = "11"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "\\Desktop\\v58\\Win" wide //weight: 4
        $x_1_2 = "Remote Host :" ascii //weight: 1
        $x_4_3 = "/Win-Spy.com" ascii //weight: 4
        $x_2_4 = "\\dll32\\csrss.exe" wide //weight: 2
        $x_2_5 = "\\dll32\\services.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_Winspy_14230_6
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Winspy"
        threat_id = "14230"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Winspy"
        severity = "11"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "\\Desktop\\v58\\Win" wide //weight: 4
        $x_4_2 = "Win-Spy Software" ascii //weight: 4
        $x_4_3 = "Win-Spy" ascii //weight: 4
        $x_1_4 = "Stealth" ascii //weight: 1
        $x_4_5 = "Win-Spy Manual.doc" wide //weight: 4
        $x_1_6 = "MonitorFireFox" ascii //weight: 1
        $x_4_7 = "start Win-Spy" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_Winspy_14230_7
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Winspy"
        threat_id = "14230"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Winspy"
        severity = "11"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "chkIncludeKeylog" ascii //weight: 3
        $x_5_2 = "Contact admin@win-spy.com to purchase additional license." wide //weight: 5
        $x_3_3 = "Remote User(logged on) will be prompted. Do you want to continue?" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

