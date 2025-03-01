rule Ransom_Win32_Blackbasta_EA_2147928345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Blackbasta.EA!MTB"
        threat_id = "2147928345"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Blackbasta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b d3 c1 ea 10 8b 88 84 00 00 00 8b 86 b8 00 00 00 88 14 01}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

