rule Ransom_Win32_NoMatter_YDQ_2147974868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/NoMatter.YDQ!MTB"
        threat_id = "2147974868"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "NoMatter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "NoMatter Ransomware" wide //weight: 5
        $x_5_2 = "YOUR UNIQUE VICTIM ID:" wide //weight: 5
        $x_5_3 = "HOW TO DECRYPT?" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

