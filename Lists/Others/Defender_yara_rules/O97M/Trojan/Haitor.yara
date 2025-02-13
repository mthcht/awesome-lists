rule Trojan_O97M_Haitor_A_2147728130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Haitor.A"
        threat_id = "2147728130"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Haitor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell StrConv(DecodeBase64(\"Y21kLmV4ZSAvYyAgcGluZyBsb2NhbGhvc3QgLW4gMTAwICYmIA==\"), vbUnicode) & Environ(\"Temp\") &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

