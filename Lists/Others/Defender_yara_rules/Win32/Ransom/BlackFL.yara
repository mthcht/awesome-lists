rule Ransom_Win32_BlackFL_YBE_2147963481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackFL.YBE!MTB"
        threat_id = "2147963481"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackFL"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hardcore blowjob" ascii //weight: 1
        $x_1_2 = "BlackFL Ransomware" wide //weight: 1
        $x_1_3 = "Servers are locked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

