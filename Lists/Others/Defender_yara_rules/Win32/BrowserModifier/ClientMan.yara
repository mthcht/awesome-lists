rule BrowserModifier_Win32_ClientMan_3754_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/ClientMan"
        threat_id = "3754"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "ClientMan"
        severity = "39"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "*google*search*q=" ascii //weight: 1
        $x_1_2 = "*search.yahoo.com" ascii //weight: 1
        $x_1_3 = "*search.live.com" ascii //weight: 1
        $x_1_4 = "*search.msn.com" ascii //weight: 1
        $x_1_5 = "72.167.52.173/?" ascii //weight: 1
        $x_1_6 = "ServerTransferSite.com/qwe.txt" ascii //weight: 1
        $x_1_7 = "BrowserHelper1.dll" ascii //weight: 1
        $x_1_8 = "ADWARE2\\_IEBrowserHelper.pas" ascii //weight: 1
        $x_1_9 = "Software\\Microsoft\\Windows\\CurrentVersion\\explorer\\Browser Helper Objects" ascii //weight: 1
        $x_1_10 = "GetClipboardData" ascii //weight: 1
        $x_1_11 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_12 = "HttpQueryInfoA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_ClientMan_3754_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/ClientMan"
        threat_id = "3754"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "ClientMan"
        severity = "39"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\Walt\\metaHelper\\_IEBrowserHelper.pas" ascii //weight: 3
        $x_2_2 = "metawrds.lst" ascii //weight: 2
        $x_3_3 = "/gaV2.php?ver=" ascii //weight: 3
        $x_1_4 = "explorer\\Browser Helper Objects\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

