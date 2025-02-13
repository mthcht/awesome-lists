rule Trojan_Win32_Merlos_2147669151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Merlos"
        threat_id = "2147669151"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Merlos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "z:\\project2012\\remotecontrol\\winhttpnet\\cqgaen\\app\\installscript\\objfre_wxp_x86\\i386\\InstallScript.pdb" ascii //weight: 1
        $x_1_2 = "akeSignBuffer" ascii //weight: 1
        $x_1_3 = "z:\\project2012\\remotecontrol\\winhttpnet\\amcy\\app\\win7\\serviceapp\\objfre_wxp_x86\\i386\\ServiceApp.pdb" ascii //weight: 1
        $x_1_4 = {c7 00 01 23 45 67 c7 40 04 89 ab cd ef c7 40 08 fe dc ba 98 c7 40 0c 76 54 32 10}  //weight: 1, accuracy: High
        $x_1_5 = {42 42 41 66 83 3a 00 75 ?? 8d 44 48 fe 85 c9 74 ?? 0f b7 08 66 85 c9 74}  //weight: 1, accuracy: Low
        $x_1_6 = "superman5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

