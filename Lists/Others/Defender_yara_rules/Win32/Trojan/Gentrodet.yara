rule Trojan_Win32_Gentrodet_B_2147709662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gentrodet.B!bit"
        threat_id = "2147709662"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gentrodet"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 0c 30 02 c8 40 3b c2 72 f6}  //weight: 1, accuracy: High
        $x_1_2 = "\\*.*.lnk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

