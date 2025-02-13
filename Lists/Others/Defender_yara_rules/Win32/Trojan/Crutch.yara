rule Trojan_Win32_Crutch_B_2147834843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Crutch.B"
        threat_id = "2147834843"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Crutch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2dropbox.rar" ascii //weight: 1
        $x_1_2 = "passwords.rar" ascii //weight: 1
        $x_1_3 = "%temp%\\mswin0001.js" ascii //weight: 1
        $x_10_4 = "crutch3.pdb" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

