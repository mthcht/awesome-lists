rule HackTool_Win64_Blueflower_A_2147684489_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Blueflower.A"
        threat_id = "2147684489"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Blueflower"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[DLL] Dumping passwords" ascii //weight: 1
        $x_1_2 = "[DLL] PasswordFilePath: %s" ascii //weight: 1
        $x_1_3 = "SECURITY\\Policy\\Secret" ascii //weight: 1
        $x_1_4 = "[DLL] LsaFilePath: %s" ascii //weight: 1
        $x_1_5 = "LsarOpenSecret" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_Blueflower_B_2147684490_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Blueflower.B"
        threat_id = "2147684490"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Blueflower"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--pleh" ascii //weight: 1
        $x_1_2 = {5b 45 58 45 5d 20 44 75 6d 70 69 6e 67 20 70 61 73 73 77 6f 72 64 73 00 5b 45 58 45 5d 20 45 78 69 74 69 6e 67}  //weight: 1, accuracy: High
        $x_1_3 = "-l : specify lsa filename" ascii //weight: 1
        $x_1_4 = "-u : specify user whose password is to be retrieved" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

