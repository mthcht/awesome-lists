rule BrowserModifier_Win32_Clodaconas_233693_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Clodaconas"
        threat_id = "233693"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Clodaconas"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ConsoleApplication1.dll" ascii //weight: 1
        $x_1_2 = "getHexStru" ascii //weight: 1
        $x_1_3 = "getMd5Jsonu" ascii //weight: 1
        $x_1_4 = "getMd5u" ascii //weight: 1
        $x_1_5 = "getUidu" ascii //weight: 1
        $x_1_6 = "isVM3" ascii //weight: 1
        $x_1_7 = "isVM4" ascii //weight: 1
        $x_1_8 = "preinstall" ascii //weight: 1
        $x_1_9 = "sendPingGet" ascii //weight: 1
        $x_1_10 = "sendPingJsonU" ascii //weight: 1
        $x_1_11 = "sendPingTooGet" ascii //weight: 1
        $x_1_12 = "uninstallFx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Clodaconas_233693_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Clodaconas"
        threat_id = "233693"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Clodaconas"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "icons/cloudguard.ico" wide //weight: 1
        $x_2_2 = "nq5n8hpbsmwzcseb5vcpvbtlau5julb8" ascii //weight: 2
        $x_1_3 = "I1iIil1Il1II" ascii //weight: 1
        $x_1_4 = "hfXPlorerBar" ascii //weight: 1
        $x_2_5 = "GreenTeamDNS.App" ascii //weight: 2
        $x_1_6 = "5da059a482fd494db3f252126fbc3d5b" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Clodaconas_233693_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Clodaconas"
        threat_id = "233693"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Clodaconas"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendPingToo" ascii //weight: 1
        $x_1_2 = "Missing General EXELabel" ascii //weight: 1
        $x_1_3 = "PostponeEXELabel" ascii //weight: 1
        $x_1_4 = "Didn't kill." ascii //weight: 1
        $x_1_5 = "DhcpNotifyConfigChange" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\5da059a482fd494db3f252126fbc3d5b" wide //weight: 1
        $x_1_7 = "Set-Cookie:\\b*{.+?}\\n" wide //weight: 1
        $x_1_8 = "Location: {[0-9]+}" wide //weight: 1
        $x_1_9 = "00:05:69" ascii //weight: 1
        $x_1_10 = "00:0C:29" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule BrowserModifier_Win32_Clodaconas_233693_3
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Clodaconas"
        threat_id = "233693"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Clodaconas"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "icons/cloudguard.ico" wide //weight: 1
        $x_2_2 = "nq5n8hpbsmwzcseb5vcpvbtlau5julb8" ascii //weight: 2
        $x_1_3 = "I1iIil1Il1II" ascii //weight: 1
        $x_1_4 = "5da059a482fd494db3f252126fbc3d5b" wide //weight: 1
        $x_1_5 = "QAlternative to a fully blown ToolTip" ascii //weight: 1
        $x_1_6 = "1f16839601aa406f8a5433ef9665d971" ascii //weight: 1
        $x_1_7 = "SetRootCertificate" ascii //weight: 1
        $x_1_8 = "GreenTeam\\wpf-notifyicon\\Windowless Sample" ascii //weight: 1
        $x_1_9 = "MbbDaliGsmDevice SetDns : An exception occurred while trying to set the DNS:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

