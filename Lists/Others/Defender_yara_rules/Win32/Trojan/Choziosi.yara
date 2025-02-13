rule Trojan_Win32_Choziosi_C_2147811043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Choziosi.C"
        threat_id = "2147811043"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Choziosi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "powershell" wide //weight: 1
        $x_2_3 = "JABlAHgAdABQAGEAdABoACAAPQAgACIA" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

