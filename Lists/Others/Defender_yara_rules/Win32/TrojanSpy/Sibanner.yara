rule TrojanSpy_Win32_Sibanner_A_2147712370_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Sibanner.A"
        threat_id = "2147712370"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Sibanner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 08 03 55 f4 8b 45 f8 8a 0a 32 4c 05 fc 8b 55 08 03 55 f4 88 0a}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 f8 33 c0 8a 44 15 fc d1 f8 8b 4d f8 88 44 0d fc 8b 55 f8 8a 44 15 fc 0c 80 8b 4d f8 88 44 0d fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Sibanner_A_2147712370_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Sibanner.A"
        threat_id = "2147712370"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Sibanner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 08 03 55 f4 8b 45 f8 8a 0a 32 4c 05 fc 8b 55 08 03 55 f4 88 0a}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 f8 33 c0 8a 44 15 fc d1 f8 8b 4d f8 88 44 0d fc 8b 55 f8 8a 44 15 fc 0c 80 8b 4d f8 88 44 0d fc}  //weight: 1, accuracy: High
        $x_1_3 = "/banner2.php?jpg=" ascii //weight: 1
        $x_1_4 = "Content-Disposition: form-data; name=\"userfile\"; filename=\"%s\"" ascii //weight: 1
        $x_1_5 = "%s\\LSP%04d.%02d.%02d_%02d.%02d.%02d.tmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

