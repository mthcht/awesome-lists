rule Trojan_MSIL_Dubfot_A_2147707721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dubfot.A"
        threat_id = "2147707721"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dubfot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\botnet\\botnet\\obj\\x86\\" ascii //weight: 1
        $x_1_2 = {26 00 70 00 63 00 61 00 64 00 69 00 3d 00 ?? ?? 26 00 64 00 64 00 6f 00 73 00 3d 00 ?? ?? 26 00 68 00 65 00 64 00 65 00 66 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_3 = {26 00 68 00 65 00 64 00 65 00 66 00 3d 00 ?? ?? 26 00 64 00 64 00 6f 00 73 00 3d 00 ?? ?? 26 00 63 00 6d 00 64 00 3d 00 ?? ?? 26 00 61 00 72 00 67 00 73 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_4 = "/botnet/kontrol.php" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

