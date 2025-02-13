rule Trojan_MSIL_Aggah_A_2147735193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Aggah.A"
        threat_id = "2147735193"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Aggah"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 65 00 6c 00 6c 00 6f 00 77 00 65 00 65 00 6e 00 68 00 61 00 67 00 67 00 61 00 2e 00 64 00 64 00 6e 00 73 00 2e 00 6e 00 65 00 74 00 2c 00 68 00 65 00 6c 00 6c 00 6f 00 77 00 65 00 65 00 6e 00 68 00 61 00 67 00 67 00 61 00 02 00 2e 00 64 00 64 00 6e 00 73 00 2e 00 6e 00 65 00 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 65 6c 6c 6f 77 65 65 6e 68 61 67 67 61 2e 64 64 6e 73 2e 6e 65 74 2c 68 65 6c 6c 6f 77 65 65 6e 68 61 67 67 61 02 00 2e 64 64 6e 73 2e 6e 65 74}  //weight: 1, accuracy: Low
        $x_1_3 = "SELECT * FROM FirewallProduct" ascii //weight: 1
        $x_1_4 = "Nuclear Explosion" ascii //weight: 1
        $x_1_5 = "2445,2445,2445" ascii //weight: 1
        $x_1_6 = "RV_MUTEX-WindowsUpdateSysten32" ascii //weight: 1
        $x_1_7 = {72 00 65 00 76 00 65 00 6e 00 67 00 65 00 72 00 78 00 03 00 2e 00 73 00 79 00 74 00 65 00 73 00 2e 00 6e 00 65 00 74 00}  //weight: 1, accuracy: Low
        $x_1_8 = {72 65 76 65 6e 67 65 72 78 03 00 2e 73 79 74 65 73 2e 6e 65 74}  //weight: 1, accuracy: Low
        $x_1_9 = "2336,2336,2336,2336,2336" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

