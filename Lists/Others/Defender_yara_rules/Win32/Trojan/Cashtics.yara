rule Trojan_Win32_Cashtics_A_2147655421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cashtics.A"
        threat_id = "2147655421"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cashtics"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "220"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "GummiModAlmighty" wide //weight: 100
        $x_100_2 = "Facebook_Private_Profile_Viewer" wide //weight: 100
        $x_50_3 = "ShareCash Tactics\\Projects" ascii //weight: 50
        $x_50_4 = "fileml.com/12A2a6" wide //weight: 50
        $x_50_5 = "fileups.net/12a6984" wide //weight: 50
        $x_20_6 = "Error 82718" wide //weight: 20
        $x_20_7 = "Facebook.Inet" wide //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_50_*) and 1 of ($x_20_*))) or
            ((1 of ($x_100_*) and 3 of ($x_50_*))) or
            ((2 of ($x_100_*) and 1 of ($x_20_*))) or
            ((2 of ($x_100_*) and 1 of ($x_50_*))) or
            (all of ($x*))
        )
}

