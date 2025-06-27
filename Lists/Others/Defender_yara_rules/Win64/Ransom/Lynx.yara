rule Ransom_Win64_Lynx_YAE_2147944778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Lynx.YAE!MTB"
        threat_id = "2147944778"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Lynx"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".lynx" wide //weight: 1
        $x_1_2 = "--encrypt-network" wide //weight: 1
        $x_1_3 = "README.txt" wide //weight: 1
        $x_1_4 = "--no-background" wide //weight: 1
        $x_10_5 = "R29vZCBhZnRlcm5vb24sIHdlIGFyZSBMeW54IEdyb3VwLg0K" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Lynx_YAF_2147944779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Lynx.YAF!MTB"
        threat_id = "2147944779"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Lynx"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "we are Lynx Group" ascii //weight: 1
        $x_1_2 = "attacked" ascii //weight: 1
        $x_1_3 = "decrypt your files" ascii //weight: 1
        $x_1_4 = "start negotiations" ascii //weight: 1
        $x_1_5 = "files stolen" ascii //weight: 1
        $x_1_6 = "interested only in money" ascii //weight: 1
        $x_10_7 = "lynxchat" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

