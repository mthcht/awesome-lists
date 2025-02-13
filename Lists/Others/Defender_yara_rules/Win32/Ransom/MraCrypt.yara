rule Ransom_Win32_MraCrypt_PA_2147808751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MraCrypt.PA!MTB"
        threat_id = "2147808751"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MraCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MRACReadMe.html" wide //weight: 1
        $x_1_2 = ".MRAC" wide //weight: 1
        $x_1_3 = {5c 4d 52 41 43 5c [0-16] 5c 4d 52 41 43 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

