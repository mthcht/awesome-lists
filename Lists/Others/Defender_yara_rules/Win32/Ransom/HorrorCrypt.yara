rule Ransom_Win32_HorrorCrypt_PAA_2147797957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/HorrorCrypt.PAA!MTB"
        threat_id = "2147797957"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "HorrorCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MBRKill" ascii //weight: 1
        $x_1_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 [0-11] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {48 6f 72 72 6f 72 54 72 6f 6a 61 6e 20 [0-4] 20 68 61 73 20 69 6e 66 65 63 74 65 64 20 79 6f 75 72 20 70 63}  //weight: 1, accuracy: Low
        $x_1_4 = {77 6d 69 63 20 70 72 6f 63 65 73 73 20 77 68 65 72 65 20 6e 61 6d 65 3d 27 [0-11] 2e 65 78 65 27 20 64 65 6c 65 74 65 20 2f 6e 6f 69 6e 74 65 72 61 63 74 69 76 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

