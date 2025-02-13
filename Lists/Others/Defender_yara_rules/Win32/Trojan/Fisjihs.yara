rule Trojan_Win32_Fisjihs_A_2147603220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fisjihs.A"
        threat_id = "2147603220"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fisjihs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://xvive.com/twiki/b.txt" ascii //weight: 1
        $x_1_2 = "strOutFile = fso.GetSpecialFolder(WindowsFolder).Path & \"\\system32\\test.log\"" ascii //weight: 1
        $x_1_3 = "fileToCopy = fso.GetSpecialFolder(WindowsFolder).Path & \"\\system32\\drivers\\etc\\hosts\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

