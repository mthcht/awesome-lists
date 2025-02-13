rule Backdoor_Win32_Hesetox_A_2147679836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hesetox.A"
        threat_id = "2147679836"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hesetox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\;?[3-9]{1}[0-9]{12,19}[D=\\u0061][0-9]{10,30}\\??" ascii //weight: 1
        $x_1_2 = {75 0f 6a 00 56 56 6a 00 ff d7 33 f6 56 ff d3 eb 02 33 f6 8d 45 ?? 50 68 02 02 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

