rule Trojan_Win32_Modiloader_SPRP_2147954584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Modiloader.SPRP!MTB"
        threat_id = "2147954584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Modiloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8d 44 24 04 50 6a 04 68 ?? ?? ?? ?? 8d 44 24 0c 50 6a 00 e8 43 34 fb ff 8b c3}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

