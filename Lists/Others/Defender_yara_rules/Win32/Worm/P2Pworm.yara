rule Worm_Win32_P2Pworm_2147555613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/P2Pworm"
        threat_id = "2147555613"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "P2Pworm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AVP_Crack" ascii //weight: 1
        $x_1_2 = "Cracker Game." ascii //weight: 1
        $x_1_3 = "XXX Virtual Sex." ascii //weight: 1
        $x_1_4 = "Credit Card." ascii //weight: 1
        $x_1_5 = "Hacker." ascii //weight: 1
        $x_1_6 = "Norton Keygen." ascii //weight: 1
        $x_1_7 = "Hotmail Hack." ascii //weight: 1
        $x_1_8 = "ICQ Hack." ascii //weight: 1
        $x_1_9 = "porn." ascii //weight: 1
        $x_1_10 = "crack." ascii //weight: 1
        $x_1_11 = "\\KMD" ascii //weight: 1
        $x_1_12 = "\\Kazza" ascii //weight: 1
        $x_1_13 = "\\Morpheus" ascii //weight: 1
        $x_1_14 = "\\Grokster" ascii //weight: 1
        $x_1_15 = "\\Bearshare" ascii //weight: 1
        $x_1_16 = "\\Gnucleus" ascii //weight: 1
        $x_1_17 = "\\Edonkey2000\\Incoming" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

