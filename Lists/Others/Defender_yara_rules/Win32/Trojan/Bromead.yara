rule Trojan_Win32_Bromead_A_2147601346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bromead.A"
        threat_id = "2147601346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bromead"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "haxorbrdream" ascii //weight: 1
        $x_1_2 = "perplex" ascii //weight: 1
        $x_2_3 = "OnPokeData" ascii //weight: 2
        $x_2_4 = "if Exist \"" ascii //weight: 2
        $x_2_5 = "Content-Transfer-Encoding: binhex40" ascii //weight: 2
        $x_2_6 = "\\Dados de aplicativos\\Microsoft\\Address Book\\" ascii //weight: 2
        $x_2_7 = "@gmail.com" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

