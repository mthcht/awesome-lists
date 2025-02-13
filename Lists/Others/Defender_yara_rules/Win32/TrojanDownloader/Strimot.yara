rule TrojanDownloader_Win32_Strimot_A_2147706356_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Strimot.A"
        threat_id = "2147706356"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Strimot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "?slots=" wide //weight: 1
        $x_1_2 = "\"; filename=\"" wide //weight: 1
        $x_1_3 = "enCrYpteD" wide //weight: 1
        $x_1_4 = "strPasswdToRecover" ascii //weight: 1
        $x_1_5 = "ANOVO2\\teste" wide //weight: 1
        $x_1_6 = {61 00 75 00 64 00 69 00 6f 00 72 00 67 00 62 00 2e 00 63 00 6f 00 6d 00 2f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 61 00 01 00 00 2f 00 73 00 65 00 74 00 75 00 70 00 35 00 2e 00 74 00 6d 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Strimot_B_2147706736_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Strimot.B"
        threat_id = "2147706736"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Strimot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xtemperr1.tmp" wide //weight: 1
        $x_1_2 = "drinksteen.com/pictures3/jota1.tmp" wide //weight: 1
        $x_1_3 = {44 00 65 00 43 00 72 00 59 00 70 00 74 00 65 00 44 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "strPasswdToRecover" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

