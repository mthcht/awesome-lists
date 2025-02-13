rule Trojan_Win32_Saycode_2147627886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Saycode"
        threat_id = "2147627886"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Saycode"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/activex/saycodeupdate.ini" ascii //weight: 1
        $x_1_2 = "__SCSWPACK_SCRUN_MUTEX__" ascii //weight: 1
        $x_1_3 = {73 68 65 6c 6c 65 78 70 2e 64 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

