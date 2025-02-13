rule Worm_Win32_Netsky_2147555600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Netsky"
        threat_id = "2147555600"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Netsky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CLSID\\{E6FB5E20-DE35-11CF-9C87-00AA005127ED}\\InProcServer32" ascii //weight: 1
        $x_1_2 = "KasperskyAv" ascii //weight: 1
        $x_1_3 = "Content-Type: application/x-zip-compressed;" ascii //weight: 1
        $x_1_4 = "RCPT TO: <" ascii //weight: 1
        $x_1_5 = "MAIL FROM: <" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_7 = "sex.doc.exe" ascii //weight: 1
        $x_1_8 = "compilation.doc.exe" ascii //weight: 1
        $x_1_9 = "dictionary.doc.exe" ascii //weight: 1
        $x_1_10 = "213.191.74.19" ascii //weight: 1
        $x_1_11 = "193.141.40.42" ascii //weight: 1
        $x_1_12 = "%s, %u %s %u %.2u:%.2u:%.2u %s%.2u%.2u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Worm_Win32_Netsky_BL_2147643966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Netsky.BL"
        threat_id = "2147643966"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Netsky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 e0 30 c1 e2 02 c1 f8 04 00 d0 88 45 d8 88 ca c0 e2 04}  //weight: 1, accuracy: High
        $x_1_2 = "C:\\Intel\\IAAnotif.exe -s" ascii //weight: 1
        $x_1_3 = {c7 03 68 65 6c 6f c7 43 04 20 6d 65 2e c7 43 08 73 6f 6d 65 c7 43 0c 70 61 6c 61 c7 43 10 63 65 2e 63}  //weight: 1, accuracy: High
        $x_1_4 = {c7 03 4d 41 49 4c c7 43 04 20 46 52 4f c7 43 08 4d 3a 3c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

