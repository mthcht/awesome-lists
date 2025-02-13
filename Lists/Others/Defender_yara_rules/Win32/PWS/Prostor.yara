rule PWS_Win32_Prostor_A_2147605626_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Prostor.gen!A"
        threat_id = "2147605626"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Prostor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "200"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {56 00 69 00 72 00 75 00 73 00 20 00 4d 00 61 00 6b 00 65 00 72 00 5c 00 56 00 69 00 72 00 75 00 73 00 20 00 4d 00 61 00 6b 00 65 00 72 00 5c 00 53 00 65 00 72 00 76 00 65 00 72 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 [0-3] 2e 00 76 00 62 00 70 00}  //weight: 100, accuracy: Low
        $x_100_2 = "Software\\Microsoft\\Windows\\Currentversion\\Run" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

