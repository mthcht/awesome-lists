rule Trojan_Win32_Vbobfus_RJ_2147849888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vbobfus.RJ!MTB"
        threat_id = "2147849888"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbobfus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 00 00 00 00 66 3d 33 c0 ba fc 30 40 00 68 6c 11 40 00 c3 b8 00 00 00 00 66 3d 33 c0 ba 44 5f 40 00 68 6c 11 40 00 c3}  //weight: 1, accuracy: High
        $x_1_2 = "wlxkbybq.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

