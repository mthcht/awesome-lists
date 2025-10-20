rule Trojan_Win32_SuspNote_MK_2147955549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspNote.MK"
        threat_id = "2147955549"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspNote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "notepad.exe " ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "HOW_TO_DECRYPT.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

