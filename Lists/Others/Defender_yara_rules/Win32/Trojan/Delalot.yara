rule Trojan_Win32_Delalot_2147495016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delalot"
        threat_id = "2147495016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delalot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "taskkill /f /im" ascii //weight: 10
        $x_10_2 = "shutdown -s" wide //weight: 10
        $x_3_3 = "erase \"C:\\Program Files" ascii //weight: 3
        $x_1_4 = "@del \\q \\s C:\\*.doc" wide //weight: 1
        $x_1_5 = "@del \\q\\ s C:\\*.txt" wide //weight: 1
        $x_1_6 = "@del \\q \\s C:\\*.mp3" wide //weight: 1
        $x_1_7 = "@del \\q \\s C:\\*.jpg" wide //weight: 1
        $x_1_8 = "@del \\q \\s C:\\*.pdf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

