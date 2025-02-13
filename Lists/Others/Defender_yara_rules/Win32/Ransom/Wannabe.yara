rule Ransom_Win32_Wannabe_SD_2147754148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Wannabe.SD!MTB"
        threat_id = "2147754148"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Wannabe"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\WannaBe.exe" ascii //weight: 1
        $x_1_2 = "\\AppData\\Local\\Google\\Chrome\\_k1.exe" ascii //weight: 1
        $x_1_3 = "\\AppData\\Local\\MSData\\k2.exe" ascii //weight: 1
        $x_1_4 = {43 3a 5c 74 65 6d 70 5f [0-32] 5c 00 2e 7a 69 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

