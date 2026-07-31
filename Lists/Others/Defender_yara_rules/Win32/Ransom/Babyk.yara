rule Ransom_Win32_Babyk_SN_2147975035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Babyk.SN!MTB"
        threat_id = "2147975035"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Babyk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/c vssadmin.exe delete shadows /all /quiet" wide //weight: 2
        $x_2_2 = "How To Restore Your Files.txt" wide //weight: 2
        $x_2_3 = "DoYouWantToHaveSexWithCuongDong" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

