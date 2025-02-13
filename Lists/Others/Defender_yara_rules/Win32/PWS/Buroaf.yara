rule PWS_Win32_Buroaf_A_2147632689_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Buroaf.A"
        threat_id = "2147632689"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Buroaf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 6b 6f 6e 74 61 6b 74 65 2e 72 75 00 [0-4] 77 77 77 2e 76 6b 6f 6e 74 61 6b 74 65 2e 72 75}  //weight: 1, accuracy: Low
        $x_1_2 = "Unhandled Exception 0x800407" ascii //weight: 1
        $x_1_3 = "http://gsmdefender.ru" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

