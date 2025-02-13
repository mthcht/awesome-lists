rule Worm_Win32_Tuhoseg_A_2147647496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Tuhoseg.A"
        threat_id = "2147647496"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Tuhoseg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ac 8b da 81 e3 ff 00 00 00 32 d8 c1 e3 02 c1 ea 08 81 e2 ff ff ff 00 33 93 ?? ?? ?? ?? e2 e1 8b c2}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 0c 00 00 00 73 63 76 68 6f 73 73 2e 65 78 65 00 e8}  //weight: 1, accuracy: High
        $x_1_3 = {c7 07 73 63 76 68 c7 47 04 6f 73 73 2e c7 47 08 65 78 65 00 c7 47 0c 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "objReg.SetStringValue(HKEY_LOCAL_MACHINE,\"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\",\"SystemIn_1\",\"%s\")" ascii //weight: 1
        $x_1_5 = {e8 0b 00 00 00 72 75 6e 32 5f 31 2e 62 61 74 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

