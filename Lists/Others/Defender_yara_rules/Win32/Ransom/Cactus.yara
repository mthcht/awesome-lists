rule Ransom_Win32_Cactus_LKV_2147846616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cactus.LKV!MTB"
        threat_id = "2147846616"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cactus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 61 00 63 00 74 00 75 00 73 00 40 00 [0-32] 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Your systems were accessed and encrypted by Cactus" wide //weight: 1
        $x_1_3 = "Your unique ID:" wide //weight: 1
        $x_1_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-255] 2e 00 6f 00 6e 00 69 00 6f 00 6e 00 2f 00 63 00 6f 00 6e 00 74 00 61 00 63 00 74 00 2f 00 43 00 61 00 63 00 74 00 75 00 73 00 5f 00 53 00 75 00 70 00 70 00 6f 00 72 00 74 00}  //weight: 1, accuracy: Low
        $x_1_5 = "CaCtUs.ReAdMe.txt" wide //weight: 1
        $x_1_6 = "vssadmin delete shadows /all /quiet" wide //weight: 1
        $x_1_7 = "cAcTuS" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

