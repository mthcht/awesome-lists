rule Trojan_Win32_Webot_2147639613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Webot"
        threat_id = "2147639613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Webot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Users\\Fakundo\\Desktop\\Visual Basic\\Sources\\WebBot\\Code" wide //weight: 10
        $x_1_2 = "Select * from AntiVirusProduct" wide //weight: 1
        $x_1_3 = "-dos.http" wide //weight: 1
        $x_1_4 = "-downexe" wide //weight: 1
        $x_10_5 = "upreports.php?&acc=ups&nick=" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

