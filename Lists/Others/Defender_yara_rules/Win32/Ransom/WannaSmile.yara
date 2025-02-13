rule Ransom_Win32_WannaSmile_GK_2147853345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WannaSmile.GK!MTB"
        threat_id = "2147853345"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WannaSmile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 04 31 8d 49 04 31 41 fc 8b 44 19 fc 31 44 11 fc 83 ef 01}  //weight: 1, accuracy: High
        $x_1_2 = "MyEncrypter2.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

