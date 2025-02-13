rule Worm_Win32_Xema_A_2147599975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Xema.gen!A"
        threat_id = "2147599975"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Xema"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5b 61 75 74 6f 72 75 6e 5d 0d 0a 73 68 65 6c 6c 65 78 65 63 75 74 65 3d 2e 5c 52 65 63 79 63 6c 65 ?? 5c}  //weight: 10, accuracy: Low
        $x_1_2 = "%sautorun.inf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Xema_B_2147600205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Xema.gen!B"
        threat_id = "2147600205"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Xema"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 00 68 00 65 00 6c 00 6c 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 3d 00 2e 00 5c 00 52 00 45 00 43 00 59 00 43 00 4c 00 45 00 ?? 00 5c 00}  //weight: 10, accuracy: Low
        $x_1_2 = "File#*" wide //weight: 1
        $x_1_3 = "&Command=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

