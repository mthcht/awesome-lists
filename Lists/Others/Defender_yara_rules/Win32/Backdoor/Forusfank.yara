rule Backdoor_Win32_Forusfank_A_2147678296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Forusfank.A"
        threat_id = "2147678296"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Forusfank"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "600"
        strings_accuracy = "High"
    strings:
        $n_300_1 = "miranda-im.org" ascii //weight: -300
        $n_300_2 = "pidgin-devel\\pidgin-" ascii //weight: -300
        $n_300_3 = "messenger@microsoft.com" ascii //weight: -300
        $x_200_4 = "rusinfo.exe" ascii //weight: 200
        $x_200_5 = "<ml l=\"1\"><d n=\"hotmail.com\"><c n=\"%s\" l=\"3\"" ascii //weight: 200
        $x_100_6 = "{870C9F42-0CAD-48A7-87AE-948D265C28F1}" ascii //weight: 100
        $x_100_7 = "GLOBAL_FINAL_DATA_FINNISHIELD_BALL" ascii //weight: 100
        $x_50_8 = "gateway.dll?SessionID=%s" ascii //weight: 50
        $x_50_9 = "ILTXC!4IXB5FB*PX" ascii //weight: 50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_200_*) and 1 of ($x_100_*) and 2 of ($x_50_*))) or
            ((2 of ($x_200_*) and 2 of ($x_100_*))) or
            (all of ($x*))
        )
}

