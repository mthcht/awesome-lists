rule Trojan_Win32_AutoHK_GP_2147938482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoHK.GP!MTB"
        threat_id = "2147938482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoHK"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4c 6f 6f 70 0a 7b 0a 49 66 20 28 20 57 69 6e 43 6c 6f 73 65 20 3c 20 52 75 6e 57 61 69 74 20 29 0a 7b 0a 4c 6f 6f 70 0a 7b 0a 49 66 20 28 20 25 41 5f 53 63 72 69 70 74 44 69 72 25 20 3c 20 52 75 6e}  //weight: 5, accuracy: High
        $x_1_2 = {20 46 69 6c 65 44 65 6c 65 74 65 20 29 0a 7b 0a 7d 0a 49 66 20 28 20 52 65 67 52 65 61 64 20 3c 20 45 6e 76 47 65 74 20 29 0a 7b 0a 7d 0a 49 66 20 28 20 44 6c 6c 43 61 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

