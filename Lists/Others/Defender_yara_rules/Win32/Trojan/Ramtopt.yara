rule Trojan_Win32_Ramtopt_B_2147629417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramtopt.B"
        threat_id = "2147629417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramtopt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 00 53 00 45 00 52 00 50 00 52 00 4f 00 46 00 49 00 4c 00 45 00 00 00 10 00 00 00 5c 00 52 00 65 00 63 00 65 00 6e 00 74}  //weight: 1, accuracy: High
        $x_1_2 = "Local Settings\\Application Data\\Identities" wide //weight: 1
        $x_1_3 = "iCrypt: A problem occured, Please Restart Windows" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

