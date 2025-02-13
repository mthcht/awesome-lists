rule Trojan_Win32_sadredi_2147725565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/sadredi"
        threat_id = "2147725565"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "sadredi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "czxhsadds\"&\".click\"&\"4\"&\"redir.com/redirect.php" wide //weight: 2
        $x_1_2 = "software\\microsoft\\windows\\currentversion\\run" wide //weight: 1
        $x_1_3 = "windowsformsapplication1\\windowsformsapplication1\\obj\\debug\\oal.pdb" wide //weight: 1
        $x_1_4 = "createobject(\"winhttp.winhttprequest.5.1\")" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

