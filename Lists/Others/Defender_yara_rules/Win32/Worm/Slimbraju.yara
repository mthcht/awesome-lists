rule Worm_Win32_Slimbraju_A_2147645505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Slimbraju.A"
        threat_id = "2147645505"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Slimbraju"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/~bl4ck/" wide //weight: 1
        $x_1_2 = "lost=Explorar" ascii //weight: 1
        $x_1_3 = {73 61 6d 70 6c 65 00 00 4a 61 62 75}  //weight: 1, accuracy: High
        $x_1_4 = {70 6c 61 79 6c 69 00 00 ff ff ff ff 06 00 00 00 73 74 2e 6d 33 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

