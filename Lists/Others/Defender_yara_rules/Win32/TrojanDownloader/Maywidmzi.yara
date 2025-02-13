rule TrojanDownloader_Win32_Maywidmzi_A_2147711680_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Maywidmzi.A"
        threat_id = "2147711680"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Maywidmzi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_12_1 = "687474703A2F2F6461726B627265616B2E6D796674702E6F72672F73746172742E637373" wide //weight: 12
        $x_12_2 = "68747470733A2F2F646C2E64726F70626F7875736572636F6E74656E742E636F6D2F732F6E3133743162313865636B723965702F73746172742E637373" wide //weight: 12
        $x_12_3 = "68747470733A2F2F676F6F676C6564726976652E636F6D2F686F73742F3042384F3366415A424C5955525A484268656C6835633049774E6B552F737461" wide //weight: 12
        $x_2_4 = "2F73746172742E637373" wide //weight: 2
        $x_2_5 = "6461726B627265616B2E6D796674702E6F7267" wide //weight: 2
        $x_1_6 = "putratS\\smargorP\\uneM tratS\\" wide //weight: 1
        $x_1_7 = "\\sndm.zip" wide //weight: 1
        $x_1_8 = "\\myapp.zip" wide //weight: 1
        $x_1_9 = "TimerSpreadMe" ascii //weight: 1
        $x_1_10 = "BtnFtpGetPlugin" ascii //weight: 1
        $x_1_11 = "ScanDrvType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_12_*))) or
            (all of ($x*))
        )
}

