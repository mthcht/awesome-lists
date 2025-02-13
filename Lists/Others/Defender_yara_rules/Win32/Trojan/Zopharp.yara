rule Trojan_Win32_Zopharp_A_2147634034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zopharp.A"
        threat_id = "2147634034"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zopharp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Pharming($dataone);" ascii //weight: 1
        $x_1_2 = "fopen(\"C:\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts\",\"w+\");" ascii //weight: 1
        $x_1_3 = "$serv = gethostbyname(\"$urldonw\");" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

