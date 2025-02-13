rule Trojan_Win32_Stealliam_A_2147617690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealliam.A"
        threat_id = "2147617690"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealliam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "36"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "wen/rb.moc.oohay.seiticoeg//:ptth" ascii //weight: 10
        $x_10_2 = "Sua mensagem foi enviada " ascii //weight: 10
        $x_10_3 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\User Agent\\Post Platform" ascii //weight: 10
        $x_1_4 = "moc.liamtoh.www" ascii //weight: 1
        $x_1_5 = "Hnavigate" ascii //weight: 1
        $x_1_6 = "hgiLniaMtcatnoC" ascii //weight: 1
        $x_1_7 = "thgiLegasseMdneS" ascii //weight: 1
        $x_5_8 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

