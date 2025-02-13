rule Trojan_Win32_Mapanna_2147603381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mapanna"
        threat_id = "2147603381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mapanna"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://<rk>" wide //weight: 1
        $x_1_2 = "http://vv" wide //weight: 1
        $x_1_3 = "<cik>" wide //weight: 1
        $x_1_4 = "<cig>" wide //weight: 1
        $x_1_5 = "<rg>" wide //weight: 1
        $x_1_6 = "{TAB}" wide //weight: 1
        $x_1_7 = {c7 85 6c ff ff ff 0b 00 00 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

