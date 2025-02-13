rule Virus_Win32_Memery_HNS_2147905529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Memery.HNS!MTB"
        threat_id = "2147905529"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Memery"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 40 00 00 00 33 c0 8d bc 24 61 02 00 00 88 9c 24 60 02 00 00 f3 ab 66 ab aa}  //weight: 1, accuracy: High
        $x_1_2 = {69 6e 66 65 63 74 20 25 73 0a 00 00 2e 45 58 45 00 00 00 00 2e 65 78 65 00 00 00 00 66 69 6e 64 20 66 69 6c 65 20 66 61 69 6c 65 64}  //weight: 1, accuracy: High
        $x_5_3 = {6f 70 65 6e 20 66 69 6c 65 20 65 72 72 6f 72 0a 00 00 00 00 6d 61 6c 6c 6f 63 20 6d 65 6d 65 72 79 20 66 61 69 6c 65 64}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

