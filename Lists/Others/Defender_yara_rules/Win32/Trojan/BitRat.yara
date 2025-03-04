rule Trojan_Win32_BitRat_NEE_2147831463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BitRat.NEE!MTB"
        threat_id = "2147831463"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BitRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 4a a2 b7 e3 04 cd 9e 91 33 b6 11 61 34 66 40 df 4f 9d 3d 14 04 4f c5 e5 3b ff cc 31 00 00 b2 fc d4 c9 f0 e4 91 44 92 6a 70 81 94 93 f7 f3 d6 5a 6b 54 49 26 45 47 9e 5d 43 1d 8c 9e 43 d6}  //weight: 1, accuracy: High
        $x_1_2 = "stdole2.tlb" ascii //weight: 1
        $x_1_3 = "LynxGrid.vbp" wide //weight: 1
        $x_1_4 = "Patricia" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

