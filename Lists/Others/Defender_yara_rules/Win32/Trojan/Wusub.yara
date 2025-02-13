rule Trojan_Win32_Wusub_A_2147733639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wusub.A"
        threat_id = "2147733639"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wusub"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 0c 06 88 1c 02 0f b6 0c 06 0f b6 d3 03 d1 0f b6 ca 8b 55 fc 0f b6 0c 01 30 0c 17 47 8a 55 0b 3b 7d f8 72}  //weight: 1, accuracy: High
        $x_1_2 = {b9 66 bd 7d b8 e8}  //weight: 1, accuracy: High
        $x_1_3 = {b9 e3 06 e0 fd e8}  //weight: 1, accuracy: High
        $x_1_4 = "/C net.exe stop foundation" wide //weight: 1
        $x_1_5 = "QHACTIVEDEFENSE.EXE" wide //weight: 1
        $x_1_6 = "BULLGUARD.EXE" wide //weight: 1
        $x_1_7 = "%s\\Microsofts Help\\wsus.exe" ascii //weight: 1
        $x_1_8 = "/C net user /domain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

