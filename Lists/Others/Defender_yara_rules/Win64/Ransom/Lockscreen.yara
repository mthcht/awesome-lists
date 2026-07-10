rule Ransom_Win64_Lockscreen_SN_2147973349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Lockscreen.SN!MTB"
        threat_id = "2147973349"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Lockscreen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Starting XOR encryption in:" wide //weight: 5
        $x_2_2 = "C:\\Users\\student\\Desktop\\svchost" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

