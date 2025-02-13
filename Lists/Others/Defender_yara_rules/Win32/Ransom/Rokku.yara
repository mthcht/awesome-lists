rule Ransom_Win32_Rokku_A_2147710269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Rokku.A"
        threat_id = "2147710269"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Rokku"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encryptor.dll" ascii //weight: 1
        $x_1_2 = "YOUR FILE HAS BEEN LOCKED" ascii //weight: 1
        $x_2_3 = "://zvnvp2rhe3ljwf2m.onion" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

