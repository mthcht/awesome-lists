rule Trojan_WinCE_Zitmo_A_2147643631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinCE/Zitmo.A"
        threat_id = "2147643631"
        type = "Trojan"
        platform = "WinCE: Windows CE platform"
        family = "Zitmo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "App Installed OK" wide //weight: 1
        $x_1_2 = "IsFirstRun" wide //weight: 1
        $x_1_3 = {73 00 65 00 74 00 20 00 61 00 64 00 6d 00 69 00 6e 00 ?? ?? 61 00 64 00 64 00 20 00 73 00 65 00 6e 00 64 00 65 00 72 00 ?? ?? 72 00 65 00 6d 00 20 00 73 00 65 00 6e 00 64 00 65 00 72 00 ?? ?? 73 00 65 00 74 00 20 00 73 00 65 00 6e 00 64 00 65 00 72 00 ?? ?? 62 00 6c 00 6f 00 63 00 6b 00}  //weight: 1, accuracy: Low
        $x_1_4 = "listnumbers.xml" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

