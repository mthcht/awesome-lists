rule Trojan_WinNT_Rootkitdrv_B_2147647350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Rootkitdrv.B"
        threat_id = "2147647350"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b c4 50 b8 7b 1d 80 7c ff d0}  //weight: 10, accuracy: High
        $x_1_2 = "InjectEye" ascii //weight: 1
        $x_1_3 = "Inject loader ok" ascii //weight: 1
        $x_1_4 = "Hook ok!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

