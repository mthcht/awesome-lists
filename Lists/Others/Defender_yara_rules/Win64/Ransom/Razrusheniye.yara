rule Ransom_Win64_Razrusheniye_YAB_2147921077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Razrusheniye.YAB!MTB"
        threat_id = "2147921077"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Razrusheniye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xmb.pythonanywhere.com" ascii //weight: 1
        $x_1_2 = "README.txt" ascii //weight: 1
        $x_10_3 = "victim of the razrusheniye ransomware" ascii //weight: 10
        $x_1_4 = "file with the .raz extension" ascii //weight: 1
        $x_1_5 = "modify encrypted files" ascii //weight: 1
        $x_1_6 = "decrypt these files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

