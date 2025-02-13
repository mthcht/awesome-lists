rule Backdoor_Win32_Degrub_A_2147708497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Degrub.A"
        threat_id = "2147708497"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Degrub"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Screen Thief Server:" ascii //weight: 1
        $x_1_2 = "Sending screen shot:" ascii //weight: 1
        $x_1_3 = "C:\\Intel\\microsoft.XML" ascii //weight: 1
        $x_1_4 = "TakeShot" ascii //weight: 1
        $x_1_5 = "keylogger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

