rule Trojan_Win32_Begravost_B_2147640593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Begravost.B"
        threat_id = "2147640593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Begravost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 96 38 1d 00 00 68 e8 03 00 00 56 ff d2 81 c7 e8 03 00 00 83 c4 08 81 ff 60 ea 00 00 76 b2}  //weight: 2, accuracy: High
        $x_1_2 = "%s&ec=%d&hr=%#08x" wide //weight: 1
        $x_1_3 = "var sBotVer=" wide //weight: 1
        $x_1_4 = "Function IEBinary_getLength(strBinary)" wide //weight: 1
        $x_1_5 = "var captcha='" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Begravost_C_2147641656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Begravost.C"
        threat_id = "2147641656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Begravost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sBotVer=" wide //weight: 1
        $x_1_2 = "<caperr/>" wide //weight: 1
        $x_1_3 = "capanswer" wide //weight: 1
        $x_1_4 = "hrExec=0x" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

