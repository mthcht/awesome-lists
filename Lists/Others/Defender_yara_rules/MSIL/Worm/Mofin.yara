rule Worm_MSIL_Mofin_A_2147681347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Mofin.A"
        threat_id = "2147681347"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mofin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 61 72 5f 73 65 68 5f 65 78 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {74 61 72 5f 73 65 6e 64 5f 66 69 6c 73 00}  //weight: 1, accuracy: High
        $x_1_3 = "\\wsystem.vx" wide //weight: 1
        $x_1_4 = "\\suchost..exe" wide //weight: 1
        $x_1_5 = "\\svchost..exe" wide //weight: 1
        $x_1_6 = {2a 00 2e 00 64 00 6f 00 63 00 ?? ?? 2a 00 2e 00 78 00 6c 00 73 00 78 00 ?? ?? 2a 00 2e 00 78 00 6c 00 73 00 ?? ?? 2a 00 2e 00 64 00 6f 00 63 00 78 00 ?? ?? 2a 00 2e 00 70 00 64 00 66 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_MSIL_Mofin_B_2147685574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Mofin.B"
        threat_id = "2147685574"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mofin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\suchost..exe" wide //weight: 1
        $x_1_2 = "\\svchost..exe" wide //weight: 1
        $x_1_3 = "infmanibila=\"[Autorun]\"&vbcrlf&\"shellexecute=wscript.exe mms.vbs\"" wide //weight: 1
        $x_1_4 = "set baso=bali.createtextfile(dalan & \"\\system32\\GroupPolicy\\Machine\\Scripts\\Startup\\mms.vbs\",2,true)" wide //weight: 1
        $x_1_5 = "If (manibila.drivetype = 1 or manibila.drivetype = 2) and manibila.path <> \"A:\" then" wide //weight: 1
        $x_1_6 = "set baso=bali.createtextfile(manibila.path & \"\\mms.vbs\",2,true)" wide //weight: 1
        $x_1_7 = "set baso=bali.createtextfile(manibila.path & \"\\autorun.inf\",2,true)" wide //weight: 1
        $x_1_8 = "baso.write infmanibila" wide //weight: 1
        $x_1_9 = "tala.regwrite \"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Pinangat\",dalan & \"\\kernel.vbs\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

