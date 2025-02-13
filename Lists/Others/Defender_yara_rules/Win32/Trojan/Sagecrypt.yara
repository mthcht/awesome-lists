rule Trojan_Win32_Sagecrypt_A_2147723931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sagecrypt.A!!Sagecrypt.gen!A"
        threat_id = "2147723931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sagecrypt"
        severity = "Critical"
        info = "Sagecrypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {61 63 79 22 20 3a 20 00 6c 61 74 22 20 3a 20 00 6c 6e 67 22 20 3a 20}  //weight: 10, accuracy: High
        $x_10_2 = "%s\\f%u.vbs" ascii //weight: 10
        $x_10_3 = {73 74 00 5c 5c 3f 5c 25 53 00 25 73 5c 66 25 75 2e 68 74 61}  //weight: 10, accuracy: High
        $x_10_4 = {7a 68 00 61 72 00 65 6e 00 64 65 00 65 73 00 66 61 00 66 72 00 69 74 00 6b 72 00 6e 6c 00 70 74 00 68 69 00 76 69 00 74 72 00 6d 73 00 6e 6f}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

