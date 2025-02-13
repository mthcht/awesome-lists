rule PWS_Win32_Mafagent_A_2147623494_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Mafagent.A"
        threat_id = "2147623494"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Mafagent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "regsvr32 /s " ascii //weight: 2
        $x_4_2 = "\\winaccestor.dat" ascii //weight: 4
        $x_5_3 = "C:\\WINDOWS\\mf6991.dll" ascii //weight: 5
        $x_4_4 = "C:\\WINDOWS\\mf*.dll" ascii //weight: 4
        $x_1_5 = "Content-Type: application/x-www-form-urlencoded" ascii //weight: 1
        $x_1_6 = "InternetOpenA" ascii //weight: 1
        $x_2_7 = "ObtainUserAgentString" ascii //weight: 2
        $x_2_8 = "GetLastActivePopup" ascii //weight: 2
        $x_2_9 = "D2-9F80-00104B1" ascii //weight: 2
        $x_2_10 = "20080214190242." ascii //weight: 2
        $x_2_11 = "53B95210-7D77-1" ascii //weight: 2
        $x_2_12 = "80-00104B107C96" ascii //weight: 2
        $x_2_13 = "CLSID\\{A8981DB9-B2B3-47D7-A890-9C9D9F4C5552}" ascii //weight: 2
        $x_10_14 = "/?ok=0&app_id=" ascii //weight: 10
        $x_10_15 = "version_id" ascii //weight: 10
        $x_10_16 = "update_id" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 8 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 7 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 8 of ($x_2_*))) or
            ((2 of ($x_10_*) and 2 of ($x_4_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_4_*) and 6 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 8 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 4 of ($x_2_*))) or
            ((3 of ($x_10_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 5 of ($x_2_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((3 of ($x_10_*) and 2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_4_*))) or
            (all of ($x*))
        )
}

