rule Ransom_Win32_Crypen_A_2147696046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crypen.A"
        threat_id = "2147696046"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crypen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 43 00 4e 00 53 00 69 00 7a 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 43 00 4e 00 45 00 78 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {43 00 4e 00 4c 00 43 00 4b 00 00 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 00 00 25 00 73 00 5c 00 25 00 73 00 5c 00 25 00 73 00 00 00 00 00 30 00 00 00 4e 00 2f 00 2f 00 41 00 00 00 00 00 79 00 65 00 73 00 00 00 66 00 69 00 6e 00 69 00 73 00 68 00 65 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {25 00 6c 00 73 00 5c 00 2a 00 2e 00 65 00 78 00 65 00 00 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00 25 00 73 00 20 00 25 00 73 00 00 00 25 00 73 00}  //weight: 1, accuracy: High
        $x_1_5 = "rtf*.xlsx*.text*.ppt*.pdf*.cdx*.cdr*.jpg*.jpeg*.png*.tiff*.dbf*." wide //weight: 1
        $x_1_6 = {00 43 4e 4c 6f 63 6b 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

