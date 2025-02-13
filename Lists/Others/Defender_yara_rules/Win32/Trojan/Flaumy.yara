rule Trojan_Win32_Flaumy_2147729606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Flaumy"
        threat_id = "2147729606"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Flaumy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c sc create foundation binpath=" ascii //weight: 1
        $x_1_2 = "\\Foundation1\\wmites.exe" ascii //weight: 1
        $x_1_3 = "bullguard.exe" ascii //weight: 1
        $x_1_4 = "\"sc.exe\" delete foundation /y" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

