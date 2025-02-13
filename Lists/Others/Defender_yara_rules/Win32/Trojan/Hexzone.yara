rule Trojan_Win32_Hexzone_A_2147615621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hexzone.A!dll"
        threat_id = "2147615621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hexzone"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "36"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "IJetVideoPlugin" ascii //weight: 10
        $x_10_2 = {64 65 6c 20 25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c ?? ?? ?? 6c 69 62 2e 64 6c 6c}  //weight: 10, accuracy: Low
        $x_10_3 = {69 66 20 65 78 69 73 74 20 25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c ?? ?? ?? 6c 69 62 2e 64 6c 6c 67 6f 74 6f 20 3a 6c 6f 6f 70}  //weight: 10, accuracy: Low
        $x_5_4 = "del delete_sh.bat" ascii //weight: 5
        $x_1_5 = "B0ED4726-5BC8-4E22-A7A8-3074A73CE64E" wide //weight: 1
        $x_1_6 = "1408E208-2AC1-42D3-9F10-78A5B36E05AC" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

