rule Trojan_Win32_Mycop_NM_2147893285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mycop.NM.MTB"
        threat_id = "2147893285"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mycop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {eb 1b 84 c0 0f 94 c0 88 44 24 ?? eb 14 85 db 74 10 8d 45 ff 3b f8 73 05 66 89 0c 7b 47 8a 44 24 13}  //weight: 5, accuracy: Low
        $x_1_2 = "jwwfaihqdu.docx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

