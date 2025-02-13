rule TrojanSpy_Win32_Bencobrab_A_2147720532_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bencobrab.A"
        threat_id = "2147720532"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bencobrab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DA7BD7082BA9DB3F57F657FA15065CF5508BB02BA94087C47B" ascii //weight: 2
        $x_2_2 = "86F06A9C53F52E438ED7EB385D384AE765E11B036783C1177DE660893C" ascii //weight: 2
        $x_2_3 = "C229B26D81DF79E960EA324383A324D171E213BA" ascii //weight: 2
        $x_2_4 = "AC2EA45D913399CA065088C2163A9C4C9BC464E472" ascii //weight: 2
        $x_1_5 = "3BAE29CFAE25AC2E65FF4B9C" ascii //weight: 1
        $x_1_6 = "389737EA4A9BC5C712B91E78E210" ascii //weight: 1
        $x_1_7 = "A33EA752E661FB5A82CD0E4E44E2669B" ascii //weight: 1
        $x_1_8 = "22409D54EE62F363FD2651A7" ascii //weight: 1
        $x_1_9 = "92EC76A057F12ABA130B74D20C3A974C" ascii //weight: 1
        $x_1_10 = "027CD67CB32E99C801" ascii //weight: 1
        $x_1_11 = "DE79D37186DC68FF56" ascii //weight: 1
        $x_1_12 = "3A449D48FE4581D27F" ascii //weight: 1
        $x_1_13 = "245FF021D90B54F65B" ascii //weight: 1
        $x_1_14 = "7691F95E95329CC904" ascii //weight: 1
        $x_1_15 = "F37FD80324B219499732" ascii //weight: 1
        $x_1_16 = "E864F51DDC75E17FA6EB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

