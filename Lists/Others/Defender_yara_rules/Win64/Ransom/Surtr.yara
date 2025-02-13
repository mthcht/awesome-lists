rule Ransom_Win64_Surtr_BH_2147838050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Surtr.BH!MTB"
        threat_id = "2147838050"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Surtr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\ProgramData\\Service\\Surtr.exe" wide //weight: 1
        $x_1_2 = "%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Surtr.exe" wide //weight: 1
        $x_1_3 = "C:\\ProgramData\\Service\\SURTR_README.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

