rule Ransom_Win32_RHRobin_AMTB_2147981237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RHRobin!AMTB"
        threat_id = "2147981237"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RHRobin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RH-Robin Ransom Note" ascii //weight: 1
        $x_1_2 = "Your files are encrypted." ascii //weight: 1
        $x_1_3 = ".rhrobin" ascii //weight: 1
        $x_1_4 = "Global\\RHRobin" ascii //weight: 1
        $x_1_5 = "README_RH.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

