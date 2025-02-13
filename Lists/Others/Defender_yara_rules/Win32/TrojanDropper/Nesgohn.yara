rule TrojanDropper_Win32_Nesgohn_B_2147638665_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Nesgohn.B"
        threat_id = "2147638665"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Nesgohn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Program Files\\microsoft frontpage\\winner.jpg" wide //weight: 1
        $x_1_2 = "Program Files\\Outlook Express\\oeimport.jpg" wide //weight: 1
        $x_1_3 = "D:\\shenlong" wide //weight: 1
        $x_1_4 = "PendingFileRenameOperations" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

