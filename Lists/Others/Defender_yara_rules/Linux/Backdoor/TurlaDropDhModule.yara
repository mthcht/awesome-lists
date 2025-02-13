rule Backdoor_Linux_TurlaDropDhModule_A_2147772536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/TurlaDropDhModule.A!!TurlaDropDhModule.A"
        threat_id = "2147772536"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "TurlaDropDhModule"
        severity = "Critical"
        info = "TurlaDropDhModule: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {da e1 01 cd d8 c9 70 af c2 e4 f2 7a 41 8b 43 39 52 9b 4b 4d e5 85 f8 49}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

