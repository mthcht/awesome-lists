rule Ransom_Win32_Pactelung_A_2147726444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Pactelung.A"
        threat_id = "2147726444"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Pactelung"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ALERT: PLEASE DO NOT SHUTDOWN COMPUTER" wide //weight: 10
        $x_1_2 = ".onion" ascii //weight: 1
        $x_1_3 = "patche(s)" wide //weight: 1
        $x_1_4 = "&& exit" ascii //weight: 1
        $x_1_5 = "/index.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

