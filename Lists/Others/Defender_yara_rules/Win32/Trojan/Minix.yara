rule Trojan_Win32_Minix_NLA_2147896863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Minix.NLA!MTB"
        threat_id = "2147896863"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Minix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c7 44 0d 00 7c 33 a2 ee 81 44 0d 00 20 a2 eb ?? ?? ?? ?? b5 8e 81 74 0d 00 3c ba 9e ?? ?? ?? ?? 81 74 0d 00 ?? ?? ?? ?? 66 f7 c3 7f ca 66 39 d8 89 bd}  //weight: 5, accuracy: Low
        $x_1_2 = "Ym.YjQA2e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

