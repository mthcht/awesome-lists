rule Worm_Win32_Zumes_A_2147631056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Zumes.A!sys"
        threat_id = "2147631056"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Zumes"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 42 9c 00 00 50 6a 44 57 ff 15 ?? ?? ?? ?? 3b c3 0f 8c}  //weight: 1, accuracy: Low
        $x_1_2 = "\\BaseNamedObjects\\SharedEventUp" wide //weight: 1
        $x_1_3 = "\\BaseNamedObjects\\SharedEventDown" wide //weight: 1
        $x_1_4 = "\\DosDevices\\Ms" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

