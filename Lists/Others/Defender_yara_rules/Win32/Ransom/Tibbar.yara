rule Ransom_Win32_Tibbar_A_2147724193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tibbar.A"
        threat_id = "2147724193"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibbar"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d 3e 1c 24 4a 74 2f 3d 17 a5 3c 92 74 23 3d 15 04 6d 96 74 21 3d 20 16 33 aa 74 1a 3d 76 09 f1 c8 74 0e 3d 14 7a 51 e2 74 0c 3d 00 5a a0 e5 75 08 83 e7 bf eb 03 83 e7 ef 8d 85 d4 fd ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {25 73 2c 23 32 20 25 73 00 00 00 41 44 4d 49 4e 24 00 00 63 73 63 63 2e 64 61 74 00 00 00 00 00 00 00 00 4f 00 6f 00 70 00 73 00 21 00 20 00 59 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_Tibbar_A_2147724193_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tibbar.A"
        threat_id = "2147724193"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibbar"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "We Guarantee that you can recover all your files safely. All you need to do is submit the payment and get the decryption password." ascii //weight: 5
        $x_2_2 = "caforssztxqzf2nm.onion" ascii //weight: 2
        $x_2_3 = "infpub.dat,#1" ascii //weight: 2
        $x_1_4 = ".3ds.7z.accdb.ai.asm.asp.aspx.avhd.back.bak.bmp.brw.c.cab.cc." ascii //weight: 1
        $x_1_5 = ".\\dcrypt" ascii //weight: 1
        $x_1_6 = "/c schtasks /Delete /F /TN rhaegal" ascii //weight: 1
        $x_1_7 = "Disable your anti-virus and anti-malware programs" ascii //weight: 1
        $x_1_8 = "Enter password#2:" ascii //weight: 1
        $x_1_9 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5clDuVFr5sQxZ+f" ascii //weight: 1
        $x_1_10 = "/Create /SC ONCE /TN viserion_%u /RU SYSTEM /TR \"%ws\" /ST %02d:%02d:00" ascii //weight: 1
        $x_1_11 = "Enter password#1:" ascii //weight: 1
        $x_1_12 = {68 2c 02 00 00 57 68 98 02 00 00 8d 8d ?? ?? ff ff 51 68 1c 00 22 00}  //weight: 1, accuracy: Low
        $x_1_13 = "@@schtasks /Delete /F /TN rhaegal" ascii //weight: 1
        $x_2_14 = "/Create /RU SYSTEM /SC ONSTART /TN rhaegal /TR" ascii //weight: 2
        $x_2_15 = "%ws C:\\Windows\\%ws,#1 %ws" ascii //weight: 2
        $x_2_16 = "rundll32 %s,#2 %s" ascii //weight: 2
        $x_1_17 = "%wswevtutil cl %ws &" ascii //weight: 1
        $x_2_18 = "/Create /SC once /TN drogon /RU SYSTEM /TR" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

