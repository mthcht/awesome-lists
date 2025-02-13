rule Trojan_Win32_Recteok_A_2147689333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Recteok.A"
        threat_id = "2147689333"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Recteok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6630663066307137" ascii //weight: 1
        $x_1_2 = "5377537753777DF4" ascii //weight: 1
        $x_1_3 = "455445544836" ascii //weight: 1
        $x_1_4 = {7c 30 7c 00 ff ff ff ff 03 00 00 00 47 4f 54 00 ff ff ff ff 06 00 00 00 67 72 61 76 61 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

