rule Backdoor_Win32_Tripshell_A_2147721182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tripshell.A"
        threat_id = "2147721182"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tripshell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "shopping.kddi-cloud.com" ascii //weight: 2
        $x_1_2 = "/news?%c=%X%X" wide //weight: 1
        $x_1_3 = "/N%u.jsp?m=%d" wide //weight: 1
        $x_2_4 = "FrontShell_[Mark].dll" ascii //weight: 2
        $x_1_5 = {00 50 72 69 6e 74 46 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

