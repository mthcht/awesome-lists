rule Trojan_Win32_Vbosfud_A_2147710394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vbosfud.A"
        threat_id = "2147710394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbosfud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":\\Users\\CIA\\Desktop\\tuti\\baa\\VB6 ARMAR 3 FUD\\BigFiles\\BigFiles.vbp" wide //weight: 1
        $x_1_2 = "http://paste.ee/r/" wide //weight: 1
        $x_1_3 = "kenaso@tx.rr.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

