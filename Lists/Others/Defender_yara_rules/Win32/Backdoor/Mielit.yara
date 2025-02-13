rule Backdoor_Win32_Mielit_A_2147648311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mielit.A"
        threat_id = "2147648311"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mielit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\lgfiles" ascii //weight: 1
        $x_1_2 = {2a 20 53 52 33 56 0a 00 76 65 72 73 69 6f 6e 65 3d 2a}  //weight: 1, accuracy: Low
        $x_1_3 = "chiavewin=Risorse di Windows" ascii //weight: 1
        $x_1_4 = "H45JY4387G5634H7TYNHC783H54735HD4HC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

