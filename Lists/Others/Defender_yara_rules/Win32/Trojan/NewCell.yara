rule Trojan_Win32_NewCell_2147839213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NewCell"
        threat_id = "2147839213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NewCell"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 73 25 73 00 00 00 00 45 58 45 00 25 73 5c 00 54 6d 70 00 65 78 70 6c 6f 72 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {50 72 65 76 69 65 77 50 61 67 65 73 00 00 00 00 53 65 74 74 69 6e 67 00}  //weight: 1, accuracy: High
        $x_2_3 = "e:\\Project\\newcell\\clip" ascii //weight: 2
        $x_1_4 = "Microsoft@ Windows@ Operating System" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NewCell_2147839213_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NewCell"
        threat_id = "2147839213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NewCell"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kylinvermilion" ascii //weight: 1
        $x_1_2 = "backserver" ascii //weight: 1
        $x_1_3 = "mainserver" ascii //weight: 1
        $x_1_4 = "Commandversion" ascii //weight: 1
        $x_1_5 = "Filterversion" ascii //weight: 1
        $x_1_6 = "alterfavorite" ascii //weight: 1
        $x_1_7 = "addshotcut" ascii //weight: 1
        $x_1_8 = "sethome" ascii //weight: 1
        $x_5_9 = "http://se.newcell.cn/Service.asmx" ascii //weight: 5
        $x_5_10 = "e:\\Project\\newcell\\svc" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 6 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

