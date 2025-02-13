rule Trojan_Win32_SuspSchtask_C_2147782852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspSchtask.C!ibt"
        threat_id = "2147782852"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSchtask"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "cmd.exe /c schtasks.exe" wide //weight: 10
        $x_5_2 = {2f 00 66 00 20 00 43 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 73 00 63 00 20 00 6d 00 69 00 6e 00 75 00 74 00 65 00 20 00 2f 00 6d 00 6f 00 [0-4] 2f 00 74 00 6e 00}  //weight: 5, accuracy: Low
        $x_5_3 = {2f 00 53 00 54 00 [0-5] 2f 00 54 00 52 00 20 00 22 00 77 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 2f 00 45 00 3a 00 76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

