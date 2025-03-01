rule TrojanSpy_Win32_Winspy_Y_2147803879_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Winspy.Y"
        threat_id = "2147803879"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Winspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\ZKing8\\WinZ\\WSP\\RenoNevada\\FTPREM\\MyFTP.vbp" wide //weight: 10
        $x_1_2 = "SOFTWARE\\AutoNewUpdate" wide //weight: 1
        $x_1_3 = "SOFTWARE\\ccAppRemXP" wide //weight: 1
        $x_1_4 = "/Win-Spy.com/www/1" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\RASOA" wide //weight: 1
        $x_1_6 = "OutlookSMTP.exe" wide //weight: 1
        $x_1_7 = "outlookrem.exe" wide //weight: 1
        $x_1_8 = "msimnSMTP.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Winspy_Z_2147804152_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Winspy.Z"
        threat_id = "2147804152"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Winspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "modAutoClean" ascii //weight: 1
        $x_1_2 = "modCheckRunningProcess" ascii //weight: 1
        $x_1_3 = "modScreenCapture" ascii //weight: 1
        $x_1_4 = "mogGetOS" ascii //weight: 1
        $x_1_5 = "modAntiSpy" ascii //weight: 1
        $x_1_6 = "mdmVFrame" ascii //weight: 1
        $x_1_7 = "clVCapture" ascii //weight: 1
        $x_1_8 = "modinifiledead" ascii //weight: 1
        $x_1_9 = "clsURLMon" ascii //weight: 1
        $x_1_10 = "tmrStartCam" ascii //weight: 1
        $x_1_11 = "cmdTestSMTP" ascii //weight: 1
        $x_1_12 = "txtEmailInterval" ascii //weight: 1
        $x_1_13 = "cmdEnableWatch" ascii //weight: 1
        $x_1_14 = "tmrOnlineTime3" ascii //weight: 1
        $x_2_15 = "CheckRunningProcess_OUTLOOK" ascii //weight: 2
        $x_2_16 = "CheckRunningProcess_IEXPLORE" ascii //weight: 2
        $x_7_17 = "\\RenoNevada\\MainMango\\Server.vbp" wide //weight: 7
        $x_2_18 = "Unhide Folder" wide //weight: 2
        $x_5_19 = "net localgroup Administrators /Add " wide //weight: 5
        $x_3_20 = "http://www.win-spy.com/update" wide //weight: 3
        $x_4_21 = "\\Temp\\desktop.exe /u" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 13 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 11 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_7_*) and 13 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_7_*) and 2 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_7_*) and 3 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_3_*) and 10 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_4_*) and 9 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_7_*) and 1 of ($x_5_*) and 8 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_5_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_5_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

