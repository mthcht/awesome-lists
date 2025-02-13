rule TrojanSpy_Win32_Pexnod_A_2147659463_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Pexnod.A"
        threat_id = "2147659463"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Pexnod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "38"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 6c 8d 55 a8 52 ff 15 ?? ?? 40 00 6a 6f 8d 45 98 50 ff 15 ?? ?? 40 00 6a 67 8d 8d 78 ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 6c 8d 45 a8 50 e8 ?? ?? fe ff 6a 6f 8d 45 98 50 e8 ?? ?? fe ff 6a 67 8d 85 78 ff ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 00 45 00 58 00 45 00 32 00 5c 00 73 00 70 00 65 00 65 00 64 00 2e 00 76 00 62 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_10_4 = {53 74 61 72 74 20 53 70 79 45 78 00}  //weight: 10, accuracy: High
        $x_10_5 = {2f 00 70 00 72 00 6f 00 78 00 79 00 2f 00 70 00 72 00 6f 00 78 00 79 00 63 00 68 00 65 00 63 00 6b 00 65 00 72 00 2f 00 63 00 6f 00 75 00 6e 00 74 00 72 00 79 00 2e 00 68 00 74 00 6d 00 00 00}  //weight: 10, accuracy: High
        $x_10_6 = {5c 00 4d 00 61 00 69 00 6c 00 31 00 2e 00 68 00 74 00 6d 00 00 00}  //weight: 10, accuracy: High
        $x_1_7 = "<title>Serial</title>" ascii //weight: 1
        $x_1_8 = "<form method=\"POST\" action=\"" ascii //weight: 1
        $x_1_9 = "PCNAME:&nbsp;" ascii //weight: 1
        $x_1_10 = "<p>NOTE:&nbsp;" ascii //weight: 1
        $x_1_11 = "<p>COUNTRY:&nbsp;" ascii //weight: 1
        $x_1_12 = "<p>USER:&nbsp;" ascii //weight: 1
        $x_1_13 = "<p>LOG:&nbsp;" ascii //weight: 1
        $x_1_14 = "<body onload=\"document.forms[0].submit();\">" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Pexnod_B_2147678657_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Pexnod.B"
        threat_id = "2147678657"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Pexnod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CAOLClipboard" ascii //weight: 1
        $x_1_2 = "modSolitaireGame" ascii //weight: 1
        $x_1_3 = "Color Spy 3.0" ascii //weight: 1
        $x_1_4 = "facultylogin" ascii //weight: 1
        $x_1_5 = "body onload=\"document.forms[0].submit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

