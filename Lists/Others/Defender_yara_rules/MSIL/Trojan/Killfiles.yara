rule Trojan_MSIL_Killfiles_PAHD_2147960102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Killfiles.PAHD!MTB"
        threat_id = "2147960102"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Killfiles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/c del /f /s /q C:\\Windows\\System32\\*.dll" wide //weight: 2
        $x_2_2 = {07 25 17 58 0b 0d 09 09 1b 63 09 1e 63 60 5a 20 ff 00 00 00 5f d2 13 04 06 08 11 04 9c 00 08 17 58 0c 08 20 22 56 00 00 fe 04 13 05 11 05 2d cf}  //weight: 2, accuracy: High
        $x_1_3 = "SystemKiller" ascii //weight: 1
        $x_1_4 = "shutdown" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

