rule Ransom_Win32_NwgenCrypt_PA_2147813958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/NwgenCrypt.PA!MTB"
        threat_id = "2147813958"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "NwgenCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c vssadmin.exe delete shadows /allA/quiet" wide //weight: 1
        $x_1_2 = ".nwgen" wide //weight: 1
        $x_1_3 = "\\How To Restore Your Files.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

