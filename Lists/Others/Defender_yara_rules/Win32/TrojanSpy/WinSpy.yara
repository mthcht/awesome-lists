rule TrojanSpy_Win32_WinSpy_2147724011_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/WinSpy"
        threat_id = "2147724011"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "WinSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TIME SPENT ONLINE REPORT" wide //weight: 1
        $x_1_2 = "WEBSITE VISITED DETAIL REPORT" wide //weight: 1
        $x_1_3 = "SitesDetail.txt" wide //weight: 1
        $x_1_4 = "PCLocation.txt" wide //weight: 1
        $x_1_5 = "TimeOnline.txt" wide //weight: 1
        $x_1_6 = "\\Capture" wide //weight: 1
        $x_1_7 = "Remote File could not be deleted" wide //weight: 1
        $x_1_8 = "Enable Watch" wide //weight: 1
        $x_1_9 = "- CMD Upl File Open -" wide //weight: 1
        $x_1_10 = "LOST STOLEN PC REPORT" wide //weight: 1
        $x_1_11 = "\\\\\\ONLINETIME " wide //weight: 1
        $x_1_12 = "\\\\\\KEYLOGS" wide //weight: 1
        $x_1_13 = "\\\\\\CHATROOM" wide //weight: 1
        $x_1_14 = "\\\\\\WEBSITED" wide //weight: 1
        $x_1_15 = "\\\\\\PCACTIVETIME" wide //weight: 1
        $x_1_16 = "\\\\\\WEBSITES" wide //weight: 1
        $x_1_17 = "Websites_Summary.txt" wide //weight: 1
        $x_1_18 = "\\Chat_log.txt" wide //weight: 1
        $x_1_19 = "Allow: GET, POST" wide //weight: 1
        $x_1_20 = "Date File Created:" wide //weight: 1
        $x_1_21 = "PC ID:" wide //weight: 1
        $x_1_22 = "KEY PRESSED REPORT" wide //weight: 1
        $x_1_23 = "Window Title:" wide //weight: 1
        $x_1_24 = "Key Pressed :" wide //weight: 1
        $x_1_25 = "PressedKeys.txt" wide //weight: 1
        $x_1_26 = {74 78 74 4d 79 4b 65 79 00}  //weight: 1, accuracy: High
        $x_1_27 = {47 6f 53 74 65 61 6c 74 68 00}  //weight: 1, accuracy: High
        $x_1_28 = {53 74 6f 70 4b 65 79 6c 6f 67 00}  //weight: 1, accuracy: High
        $x_1_29 = "{LeftWinKey}" wide //weight: 1
        $x_1_30 = "{LeftAlt}" wide //weight: 1
        $x_1_31 = "SendFile:" wide //weight: 1
        $x_1_32 = "Save Snap:" wide //weight: 1
        $x_1_33 = "Check Cam:" wide //weight: 1
        $x_1_34 = "\\ChatReport.txt" wide //weight: 1
        $x_1_35 = "\\SitesSummary.txt" wide //weight: 1
        $x_1_36 = "Accessories\\Common\\*.txt" wide //weight: 1
        $x_1_37 = {53 54 4f 50 43 41 4d 20 53 54 41 52 54 43 41 4d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

