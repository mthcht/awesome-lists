rule Ransom_Win32_GoRanp_ST_2147763968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GoRanp.ST!MTB"
        threat_id = "2147763968"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GoRanp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "your all files have been encrypted" ascii //weight: 1
        $x_1_2 = "if you want you files back" ascii //weight: 1
        $x_1_3 = "email us here :" ascii //weight: 1
        $x_1_4 = "Fuck you!!!" ascii //weight: 1
        $x_1_5 = "\\Desktop\\Fuck.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

