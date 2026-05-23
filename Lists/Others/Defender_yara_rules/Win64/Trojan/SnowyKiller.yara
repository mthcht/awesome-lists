rule Trojan_Win64_SnowyKiller_A_2147970040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SnowyKiller.A"
        threat_id = "2147970040"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SnowyKiller"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 5c 00 2e 00 5c 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 43 00 74 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "C:\\Users\\Chinggis\\Desktop\\Win 11 Latest NEw killer" ascii //weight: 1
        $x_1_3 = "powershell -WindowStyle Hidden -Command \"(Get-Process " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

