rule BrowserModifier_Win32_Knowledgelink_143785_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Knowledgelink"
        threat_id = "143785"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Knowledgelink"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Explorer\\Browser Helper Objects\\{8AF33C51-E933-40B3-BE74-E9E630C6060C}" ascii //weight: 1
        $x_1_2 = {70 6f 70 62 65 66 6f 72 65 74 69 6d 65 3d 00 00 70 6f 70 75 72 6c 3d 00 70 6f 70 6e 65 77 3d}  //weight: 1, accuracy: High
        $x_1_3 = "&kind=updatecheck" ascii //weight: 1
        $x_1_4 = {6b 6e 6f 77 6c 65 64 67 65 6c 69 6e 6b 73 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

