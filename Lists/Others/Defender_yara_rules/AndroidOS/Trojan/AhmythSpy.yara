rule Trojan_AndroidOS_AhmythSpy_K_2147835060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/AhmythSpy.K"
        threat_id = "2147835060"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "AhmythSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ServicePermGerais" ascii //weight: 2
        $x_2_2 = "x0000notif" ascii //weight: 2
        $x_2_3 = "codigosbnksok" ascii //weight: 2
        $x_2_4 = "x0000scrnlk" ascii //weight: 2
        $x_2_5 = "ActivityBNK" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

