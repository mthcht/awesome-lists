rule TrojanDownloader_Win32_Pipsek_A_2147643477_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pipsek.gen!A"
        threat_id = "2147643477"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pipsek"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "systemdebug.exe" ascii //weight: 1
        $x_1_2 = "usp10.dll" ascii //weight: 1
        $x_1_3 = "lqcyc52.cyc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Pipsek_B_2147643478_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pipsek.B"
        threat_id = "2147643478"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pipsek"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 dd 6d 00 ff d7 4e 75 ec 6a 00 ff 15 ?? ?? ?? ?? 5f 5e cc}  //weight: 1, accuracy: Low
        $x_1_2 = {b0 6c 88 44 24 1b 88 44 24 23 88 44 24 0a 88 44 24 10 88 44 24 11 b0 4f 53 b1 6f}  //weight: 1, accuracy: High
        $x_1_3 = "%s?mac=%s&ver=%s" ascii //weight: 1
        $x_1_4 = {56 56 56 56 56 56 00 00 43 43 43 43 43 43 00 00 5c 54 61 73 6b 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Pipsek_C_2147643479_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pipsek.C"
        threat_id = "2147643479"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pipsek"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " goto # $" ascii //weight: 1
        $x_1_2 = "c:\\te .bat" ascii //weight: 1
        $x_1_3 = "bug.7e`CYCS%?" ascii //weight: 1
        $x_1_4 = "keybd_ev z" ascii //weight: 1
        $x_1_5 = "\\lqcyc5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Pipsek_B_2147645005_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pipsek.gen!B"
        threat_id = "2147645005"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pipsek"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CycCtrl.exe" ascii //weight: 1
        $x_1_2 = "usp10.dll" ascii //weight: 1
        $x_1_3 = "lqcyc52.cyc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

