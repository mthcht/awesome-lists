rule Worm_Win32_Skypoot_A_2147711555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Skypoot.A"
        threat_id = "2147711555"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Skypoot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 53 6b 79 70 6c 65 78 00}  //weight: 1, accuracy: High
        $x_1_2 = "\\Home\\Code\\Skyplex" ascii //weight: 1
        $x_1_3 = "kthxbye.bat" ascii //weight: 1
        $x_1_4 = "TZapCommunicator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

