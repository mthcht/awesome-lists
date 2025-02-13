rule Backdoor_Win32_Cadelspy_PA_2147782228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Cadelspy.PA!MTB"
        threat_id = "2147782228"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Cadelspy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 68 20 02 00 00 6a 20 6a 02 8d 45 ?? 66 ?? ?? ?? ?? 05 50}  //weight: 1, accuracy: Low
        $x_1_2 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" wide //weight: 1
        $x_1_3 = "C:\\Windows\\SysEvent.exe" wide //weight: 1
        $x_1_4 = {5c 70 69 65 63 65 6f 66 73 68 69 74 5c [0-16] 5c 70 69 65 63 65 6f 66 73 68 69 74 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

