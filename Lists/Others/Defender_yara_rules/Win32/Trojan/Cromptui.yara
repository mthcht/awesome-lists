rule Trojan_Win32_Cromptui_A_2147646264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cromptui.A"
        threat_id = "2147646264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cromptui"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d b7 00 00 00 0f 84 4f 0d 00 00 68 a9 1e 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 02 32 c6 45 03 31 eb 10 c6 45 00 31 c6 45 01 32}  //weight: 1, accuracy: High
        $x_1_3 = {6a 50 50 55 ff 54 24 70 6a 00 8b c8 6a 00 6a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Cromptui_B_2147654497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cromptui.B"
        threat_id = "2147654497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cromptui"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HTTPW-GNIK" ascii //weight: 1
        $x_1_2 = "TEMP\\\\adobeupd.exe" ascii //weight: 1
        $x_1_3 = "\\Adobe Center.lnk" ascii //weight: 1
        $x_1_4 = "\\netbn.exe" ascii //weight: 1
        $x_1_5 = "\\netdc.exe" ascii //weight: 1
        $x_1_6 = "/cgi-bin/CMS_ClearAll.cgi" ascii //weight: 1
        $x_1_7 = "/cgi-bin/CMS_ListImg.cgi" ascii //weight: 1
        $x_1_8 = "/cgi-bin/CMS_SubitAll.cgi" ascii //weight: 1
        $x_1_9 = "RMTCURR" ascii //weight: 1
        $x_1_10 = "if exist \"C:\\TEMP\\\\adobeupd.exe\" del /q \"C:\\TEMP\\\\adobeupd.exe\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

