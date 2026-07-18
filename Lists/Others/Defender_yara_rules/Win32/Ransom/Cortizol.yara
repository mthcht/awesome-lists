rule Ransom_Win32_Cortizol_YDQ_2147973569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cortizol.YDQ!MTB"
        threat_id = "2147973569"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cortizol"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HOW_TO_RECOVER" wide //weight: 1
        $x_1_2 = "Cortizol Ransomware" wide //weight: 1
        $x_1_3 = "ULTRA ENCRYPTION STARTED" wide //weight: 1
        $x_1_4 = "DESTRUCTION COMPLETE!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

