rule Worm_MSIL_Cribz_A_2147689730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Cribz.A"
        threat_id = "2147689730"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cribz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 68 75 74 69 6c 2e 64 65 66 61 75 6c 74 2e 72 65 67 00}  //weight: 1, accuracy: High
        $x_1_2 = "\"Level1Remove\"=\".bat;.com;.exe;.js;.jse;.reg;.vbe;.vbs\"" ascii //weight: 1
        $x_1_3 = "\"FirewallDisableNotify\"=dword:00000001" ascii //weight: 1
        $x_1_4 = {5c 4b 61 73 70 65 72 73 6b 79 41 6e 74 69 56 69 72 75 73 5d 0d 0a 22 44 69 73 61 62 6c 65 4d 6f 6e 69 74 6f 72 69 6e 67 22 3d 64 77 6f 72 64 3a 30 30 30 30 30 30 30 31}  //weight: 1, accuracy: High
        $x_1_5 = {5c 53 65 72 76 69 63 65 73 5c 48 54 54 50 46 69 6c 74 65 72 5d 0d 0a 22 53 74 61 72 74 22 3d 64 77 6f 72 64 3a 30 30 30 30 30 30 30 32}  //weight: 1, accuracy: High
        $x_1_6 = "\"ServiceMain\"=\"SvchostEntry_W32Time\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

