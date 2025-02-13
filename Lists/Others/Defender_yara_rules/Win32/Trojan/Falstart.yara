rule Trojan_Win32_Falstart_A_2147659622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Falstart.A"
        threat_id = "2147659622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Falstart"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "facebook hack V" ascii //weight: 1
        $x_1_2 = "*   P  a  s  s  w  o  r  d  *" ascii //weight: 1
        $x_1_3 = "Victim's E-Mail" ascii //weight: 1
        $x_1_4 = "By : Mr.JuBa  and  D.Meta" ascii //weight: 1
        $x_1_5 = "read me.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

