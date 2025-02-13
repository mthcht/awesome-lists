rule Worm_Win32_Bosidome_A_2147655892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bosidome.A"
        threat_id = "2147655892"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bosidome"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mBitcoinMinage" ascii //weight: 1
        $x_1_2 = "mSpreadP2P" ascii //weight: 1
        $x_1_3 = "mSpreadUsb" ascii //weight: 1
        $x_1_4 = "mFudAutorun" ascii //weight: 1
        $x_1_5 = "JavaUpdate.exe /s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

