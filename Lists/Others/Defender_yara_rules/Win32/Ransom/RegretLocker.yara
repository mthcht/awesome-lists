rule Ransom_Win32_RegretLocker_DA_2147767267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RegretLocker.DA!MTB"
        threat_id = "2147767267"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RegretLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RegretLocker" ascii //weight: 1
        $x_1_2 = ".mouse" ascii //weight: 1
        $x_1_3 = "HOW TO RESTORE FILES.TXT" ascii //weight: 1
        $x_1_4 = "All your files were encrypted " ascii //weight: 1
        $x_1_5 = "@ctemplar.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

