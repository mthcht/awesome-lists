rule Trojan_Win64_Gosheas_A_2147955248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Gosheas.A"
        threat_id = "2147955248"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Gosheas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.shellcodeEncoded" ascii //weight: 1
        $x_1_2 = "main.xorKey" ascii //weight: 1
        $x_1_3 = "bypass.go" ascii //weight: 1
        $x_1_4 = {0f b6 3c 30 31 d7 40 88 3c 30 48 ff c6 48 39 f3 7f ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

