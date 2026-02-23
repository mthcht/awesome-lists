rule Ransom_Win64_ISIS_AMTB_2147963502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/ISIS!AMTB"
        threat_id = "2147963502"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "ISIS"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ISISRansom.pdb" ascii //weight: 1
        $x_1_2 = "ISIS_RANSOM_NOTE.txt" ascii //weight: 1
        $x_1_3 = "isis_wallpaper.bmp" ascii //weight: 1
        $x_1_4 = "ISIS RANSOMWARE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

