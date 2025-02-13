rule Ransom_Win32_Ocelocker_PAA_2147814503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ocelocker.PAA!MTB"
        threat_id = "2147814503"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ocelocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ransomware" ascii //weight: 1
        $x_1_2 = "Ocelocker.pdb" ascii //weight: 1
        $x_1_3 = "Writing ransom note" ascii //weight: 1
        $x_1_4 = "All of your files are encrypted!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

