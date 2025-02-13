rule Backdoor_MSIL_Rifeds_A_2147683995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Rifeds.A"
        threat_id = "2147683995"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rifeds"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://188.239.10.183/" wide //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "<CapsLock=On>" wide //weight: 1
        $x_1_4 = "<CapsLock=Off>" wide //weight: 1
        $x_1_5 = "<RMouse>" wide //weight: 1
        $x_1_6 = "<Ins>" wide //weight: 1
        $x_1_7 = {04 73 54 00 00 0a 0a 17 8d 41 00 00 01 13 0a 11 0a 16 1f 5c 9d 11 0a 0c 03 08 6f 4c 00 00 0a 0d 72 1f 02 00 70 13 04 09 16 6f 4d 00 00 0a 6f 4e 00 00 0a 72 2b 02 00 70 28 4f 00 00 0a 2c 40 16 8c 2a 00 00 01 72 3b 02 00 70 28 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

