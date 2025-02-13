rule HackTool_Win64_Cryptor_JZ_2147904603_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Cryptor.JZ!MTB"
        threat_id = "2147904603"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Cryptor"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encrypt file" ascii //weight: 1
        $x_1_2 = "decrypt file" ascii //weight: 1
        $x_1_3 = "test encryption" ascii //weight: 1
        $x_1_4 = "load encrypted dll" ascii //weight: 1
        $x_1_5 = "myfile.txt.enc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

