rule TrojanSpy_MSIL_Popclik_A_2147653270_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Popclik.A"
        threat_id = "2147653270"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Popclik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 4d 5f 4b 45 59 55 50 00 57 4d 5f 4b 45 59 44 4f 57 4e 00 57 4d 5f 53 59 53 4b 45 59 44 4f 57 4e 00 57 4d 5f 53 59 53 4b 45 59 55 50 00}  //weight: 1, accuracy: High
        $x_1_2 = "/?kw=track" wide //weight: 1
        $x_1_3 = "/tmp.exe" wide //weight: 1
        $x_1_4 = "\\work\\companies\\chaseprograms\\adleet.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

