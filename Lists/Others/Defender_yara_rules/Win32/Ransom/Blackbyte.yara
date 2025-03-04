rule Ransom_Win32_BlackByte_SA_2147812958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackByte.SA"
        threat_id = "2147812958"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackByte"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "main.delshadows" ascii //weight: 5
        $x_5_2 = "main.stopallsvc" ascii //weight: 5
        $x_5_3 = "main.kill" ascii //weight: 5
        $x_5_4 = "main.encrypt" ascii //weight: 5
        $x_5_5 = "main.destroy" ascii //weight: 5
        $x_5_6 = "main.listservices" ascii //weight: 5
        $x_5_7 = "main.lanscan" ascii //weight: 5
        $x_5_8 = "main.parsenetview" ascii //weight: 5
        $x_5_9 = "main.shownote" ascii //weight: 5
        $x_5_10 = "main.pognali" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

