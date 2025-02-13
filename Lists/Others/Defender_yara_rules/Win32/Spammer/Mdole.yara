rule Spammer_Win32_Mdole_2147645456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Mdole"
        threat_id = "2147645456"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Mdole"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LoDM855" wide //weight: 1
        $x_1_2 = "http://173.192.182.46/~videos/" wide //weight: 1
        $x_1_3 = "default.aspx?wa=wsignin1.0" wide //weight: 1
        $x_1_4 = "default.aspx?rru=inbox" wide //weight: 1
        $x_1_5 = "http://mail.live.com/?rru=contacts" ascii //weight: 1
        $x_1_6 = "ContactMainLight.aspx?ContactsSortBy=FileAs&amp;Page=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

