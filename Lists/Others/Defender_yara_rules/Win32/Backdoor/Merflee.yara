rule Backdoor_Win32_Merflee_A_2147694228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Merflee.A!dha"
        threat_id = "2147694228"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Merflee"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ItIsTheEndOfTheWorldAndIFeelFineREM" ascii //weight: 1
        $x_1_2 = "apec.dnsfreestore.com" ascii //weight: 1
        $x_1_3 = "/microsoft/product/windowsupdate/aspx" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Merflee_B_2147696351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Merflee.B!dha"
        threat_id = "2147696351"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Merflee"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1000"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dAndIFeelFineREM" ascii //weight: 1
        $x_1_2 = "BS2Proxy Error: Requested host is not available. Please try again later.." ascii //weight: 1
        $x_1_3 = "abe2869f-9b47-4cd9-a358-c22904dba7f7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

