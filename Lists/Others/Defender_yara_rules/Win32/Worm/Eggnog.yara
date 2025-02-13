rule Worm_Win32_Eggnog_E_2147827433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Eggnog.E!MTB"
        threat_id = "2147827433"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Eggnog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 00 c4 3d 40 00 88 3d 40 00 a0 54 40 00 1c 54 40}  //weight: 1, accuracy: High
        $x_1_2 = "Worm.P2P.Google" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\LimeWire" ascii //weight: 1
        $x_1_4 = "Uninstall\\eDonkey2000" ascii //weight: 1
        $x_1_5 = "Software\\Xolox" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

