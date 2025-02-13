rule Trojan_Win32_Drupirel_A_2147631723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Drupirel.A"
        threat_id = "2147631723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Drupirel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "theurl" wide //weight: 1
        $x_1_2 = "thedate" wide //weight: 1
        $x_1_3 = "theip" wide //weight: 1
        $x_1_4 = "repip" wide //weight: 1
        $x_1_5 = "[InternetShortcut]" ascii //weight: 1
        $x_1_6 = "system32\\drivers" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

