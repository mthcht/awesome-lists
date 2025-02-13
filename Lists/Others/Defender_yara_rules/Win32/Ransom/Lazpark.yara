rule Ransom_Win32_Lazpark_DA_2147775564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lazpark.DA!MTB"
        threat_id = "2147775564"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazpark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your network is penetrated" ascii //weight: 1
        $x_1_2 = "lazparking-message.txt" ascii //weight: 1
        $x_1_3 = "ransomware" ascii //weight: 1
        $x_1_4 = "CHACHA20" ascii //weight: 1
        $x_1_5 = "fake.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

