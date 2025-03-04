rule Trojan_Win32_Bazzarldr_GU_2147765667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bazzarldr.GU!MTB"
        threat_id = "2147765667"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bazzarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {10 00 00 c7 44 [0-2] 00 00 00 00 89 04 [0-2] ff d3 8b 4d [0-2] 89 c7 89 c3 f3 a4 83 ec [0-2] 89 5c [0-2] c7 44 [0-2] 00 00 00 00 8b 45 [0-2] c7 44 [0-2] 01 00 00 00 c7 44 [0-2] 00 00 00 00 89 44 [0-2] 8d 45 [0-2] 89 44 [0-2] 8b 45 [0-2] 89 04 [0-2] ff 15 [0-4] 83 ec [0-2] 85 c0 0f}  //weight: 5, accuracy: Low
        $x_1_2 = "VirtualAllocExNuma" ascii //weight: 1
        $x_1_3 = "CryptEncrypt" ascii //weight: 1
        $x_1_4 = "memcpy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

