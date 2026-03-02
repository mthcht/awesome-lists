rule Trojan_Win32_Sidewinder_PGSW_2147963945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sidewinder.PGSW!MTB"
        threat_id = "2147963945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sidewinder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "zb0QH9rW91uU1H1HXN93a3ZKO4x64P3Ji4Xx4486KA6VjdI4796CN610yJ3uHdIC568fLcOIK3VD94A7oB383Tjbd3CCbz52QnAf0vjXf7dRsgqISARl" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

