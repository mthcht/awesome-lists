rule Ransom_Win32_Apocalypse_A_2147718607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Apocalypse.A!bit"
        threat_id = "2147718607"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Apocalypse"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd.exe /c vssadmin delete shadows /all /quiet" wide //weight: 1
        $x_1_2 = ":Zone.Identifier" wide //weight: 1
        $x_1_3 = {4c 00 6f 00 63 00 61 00 6c 00 5c 00 [0-21] 5f 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\Windows NT\\explorer.exe" wide //weight: 1
        $x_1_5 = {59 6f 75 20 77 69 6c 6c 20 68 61 76 65 20 74 6f 20 6f 72 64 65 72 20 74 68 65 20 55 6e 6c 6f 63 6b 2d 50 61 73 73 77 6f 72 64 20 61 6e 64 20 74 68 65 20 [0-21] 20 44 65 63 72 79 70 74 69 6f 6e 20 53 6f 66 74 77 61 72 65 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

