rule Trojan_Win32_SusNote_MK_2147954084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusNote.MK"
        threat_id = "2147954084"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusNote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "notepad.exe " ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "HOW_TO_DECRYPT.txt" ascii //weight: 1
        $n_1_4 = "9453e881-26a8-4973-ba2e-76269e901d0s" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

