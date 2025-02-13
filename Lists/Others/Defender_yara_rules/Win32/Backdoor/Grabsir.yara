rule Backdoor_Win32_Grabsir_A_2147718972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Grabsir.A"
        threat_id = "2147718972"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Grabsir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ST Service Scheduling" wide //weight: 3
        $x_2_2 = "%s\\newgate.txt" wide //weight: 2
        $x_2_3 = "&%sda%sta=%d%s%d" ascii //weight: 2
        $x_1_4 = "abe2869f-9b47-4cd9-a358-c22904dba7f7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

