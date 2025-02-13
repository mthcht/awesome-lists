rule Trojan_Win32_Darhack_A_2147656608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Darhack.A"
        threat_id = "2147656608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Darhack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Crypt\\DarEye" ascii //weight: 1
        $x_1_2 = "Cracked by" ascii //weight: 1
        $x_1_3 = {79 71 63 63 62 6e [0-8] 63 72 65 6d 65}  //weight: 1, accuracy: Low
        $x_1_4 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

