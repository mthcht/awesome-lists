rule Worm_Win32_Sokern_A_2147684408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Sokern.A"
        threat_id = "2147684408"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Sokern"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "F-Secure Gatekeeper Handler Starter" ascii //weight: 1
        $x_1_2 = "JC\\ntsokrnl.vbp" wide //weight: 1
        $x_1_3 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "K:\\Autorun.inf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

